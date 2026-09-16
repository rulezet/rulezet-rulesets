rule TTP_XOR_MULT_DOSStub_ea74 {
  strings:
    $key_ea74 = { be 1c [2] ca 04 [2] 8d 06 [2] ca 17 [2] 84 1b [2] 88 11 [2] 9f 1a [2] 84 54 [2] b9 }

  condition:
    any of them
}