rule TTP_XOR_MULT_DOSStub_0f1a {
  strings:
    $key_0f1a = { 5b 72 [2] 2f 6a [2] 68 68 [2] 2f 79 [2] 61 75 [2] 6d 7f [2] 7a 74 [2] 61 3a [2] 5c }

  condition:
    any of them
}