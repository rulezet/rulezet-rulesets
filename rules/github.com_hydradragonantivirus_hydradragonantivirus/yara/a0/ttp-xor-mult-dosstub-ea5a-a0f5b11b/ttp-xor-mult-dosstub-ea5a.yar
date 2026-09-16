rule TTP_XOR_MULT_DOSStub_ea5a {
  strings:
    $key_ea5a = { be 32 [2] ca 2a [2] 8d 28 [2] ca 39 [2] 84 35 [2] 88 3f [2] 9f 34 [2] 84 7a [2] b9 }

  condition:
    any of them
}