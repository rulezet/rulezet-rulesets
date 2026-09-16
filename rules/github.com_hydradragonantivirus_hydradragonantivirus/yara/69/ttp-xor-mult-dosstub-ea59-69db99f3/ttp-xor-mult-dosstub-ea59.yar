rule TTP_XOR_MULT_DOSStub_ea59 {
  strings:
    $key_ea59 = { be 31 [2] ca 29 [2] 8d 2b [2] ca 3a [2] 84 36 [2] 88 3c [2] 9f 37 [2] 84 79 [2] b9 }

  condition:
    any of them
}