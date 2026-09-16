rule TTP_XOR_MULT_DOSStub_ea08 {
  strings:
    $key_ea08 = { be 60 [2] ca 78 [2] 8d 7a [2] ca 6b [2] 84 67 [2] 88 6d [2] 9f 66 [2] 84 28 [2] b9 }

  condition:
    any of them
}