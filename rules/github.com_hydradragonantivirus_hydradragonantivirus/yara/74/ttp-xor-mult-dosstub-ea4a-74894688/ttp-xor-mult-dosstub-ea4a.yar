rule TTP_XOR_MULT_DOSStub_ea4a {
  strings:
    $key_ea4a = { be 22 [2] ca 3a [2] 8d 38 [2] ca 29 [2] 84 25 [2] 88 2f [2] 9f 24 [2] 84 6a [2] b9 }

  condition:
    any of them
}