rule TTP_XOR_MULT_DOSStub_c452 {
  strings:
    $key_c452 = { 90 3a [2] e4 22 [2] a3 20 [2] e4 31 [2] aa 3d [2] a6 37 [2] b1 3c [2] aa 72 [2] 97 }

  condition:
    any of them
}