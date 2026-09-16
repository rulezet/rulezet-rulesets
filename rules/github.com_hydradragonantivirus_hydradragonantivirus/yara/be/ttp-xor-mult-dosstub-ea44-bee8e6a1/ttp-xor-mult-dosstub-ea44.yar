rule TTP_XOR_MULT_DOSStub_ea44 {
  strings:
    $key_ea44 = { be 2c [2] ca 34 [2] 8d 36 [2] ca 27 [2] 84 2b [2] 88 21 [2] 9f 2a [2] 84 64 [2] b9 }

  condition:
    any of them
}