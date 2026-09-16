rule TTP_XOR_MULT_DOSStub_e543 {
  strings:
    $key_e543 = { b1 2b [2] c5 33 [2] 82 31 [2] c5 20 [2] 8b 2c [2] 87 26 [2] 90 2d [2] 8b 63 [2] b6 }

  condition:
    any of them
}