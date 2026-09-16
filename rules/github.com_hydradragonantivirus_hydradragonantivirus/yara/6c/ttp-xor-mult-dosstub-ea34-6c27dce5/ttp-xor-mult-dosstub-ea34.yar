rule TTP_XOR_MULT_DOSStub_ea34 {
  strings:
    $key_ea34 = { be 5c [2] ca 44 [2] 8d 46 [2] ca 57 [2] 84 5b [2] 88 51 [2] 9f 5a [2] 84 14 [2] b9 }

  condition:
    any of them
}