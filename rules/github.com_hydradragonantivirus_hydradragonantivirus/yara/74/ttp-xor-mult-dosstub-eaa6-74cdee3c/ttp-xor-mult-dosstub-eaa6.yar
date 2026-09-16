rule TTP_XOR_MULT_DOSStub_eaa6 {
  strings:
    $key_eaa6 = { be ce [2] ca d6 [2] 8d d4 [2] ca c5 [2] 84 c9 [2] 88 c3 [2] 9f c8 [2] 84 86 [2] b9 }

  condition:
    any of them
}