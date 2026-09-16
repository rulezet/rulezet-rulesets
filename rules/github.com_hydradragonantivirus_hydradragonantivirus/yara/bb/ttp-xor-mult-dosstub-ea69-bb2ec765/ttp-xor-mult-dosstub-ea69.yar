rule TTP_XOR_MULT_DOSStub_ea69 {
  strings:
    $key_ea69 = { be 01 [2] ca 19 [2] 8d 1b [2] ca 0a [2] 84 06 [2] 88 0c [2] 9f 07 [2] 84 49 [2] b9 }

  condition:
    any of them
}