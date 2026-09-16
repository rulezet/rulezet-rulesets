rule TTP_XOR_MULT_DOSStub_e153 {
  strings:
    $key_e153 = { b5 3b [2] c1 23 [2] 86 21 [2] c1 30 [2] 8f 3c [2] 83 36 [2] 94 3d [2] 8f 73 [2] b2 }

  condition:
    any of them
}