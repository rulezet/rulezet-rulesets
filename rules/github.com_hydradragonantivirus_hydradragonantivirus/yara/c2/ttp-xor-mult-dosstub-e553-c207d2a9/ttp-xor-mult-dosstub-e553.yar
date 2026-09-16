rule TTP_XOR_MULT_DOSStub_e553 {
  strings:
    $key_e553 = { b1 3b [2] c5 23 [2] 82 21 [2] c5 30 [2] 8b 3c [2] 87 36 [2] 90 3d [2] 8b 73 [2] b6 }

  condition:
    any of them
}