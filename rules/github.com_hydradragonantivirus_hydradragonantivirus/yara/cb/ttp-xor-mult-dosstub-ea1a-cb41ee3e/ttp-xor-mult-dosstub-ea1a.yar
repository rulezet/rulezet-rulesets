rule TTP_XOR_MULT_DOSStub_ea1a {
  strings:
    $key_ea1a = { be 72 [2] ca 6a [2] 8d 68 [2] ca 79 [2] 84 75 [2] 88 7f [2] 9f 74 [2] 84 3a [2] b9 }

  condition:
    any of them
}