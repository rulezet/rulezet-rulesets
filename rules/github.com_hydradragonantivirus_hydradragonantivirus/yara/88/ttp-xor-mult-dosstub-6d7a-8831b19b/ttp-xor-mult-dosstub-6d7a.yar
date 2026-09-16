rule TTP_XOR_MULT_DOSStub_6d7a {
  strings:
    $key_6d7a = { 39 12 [2] 4d 0a [2] 0a 08 [2] 4d 19 [2] 03 15 [2] 0f 1f [2] 18 14 [2] 03 5a [2] 3e }

  condition:
    any of them
}