rule TTP_XOR_MULT_DOSStub_ea42 {
  strings:
    $key_ea42 = { be 2a [2] ca 32 [2] 8d 30 [2] ca 21 [2] 84 2d [2] 88 27 [2] 9f 2c [2] 84 62 [2] b9 }

  condition:
    any of them
}