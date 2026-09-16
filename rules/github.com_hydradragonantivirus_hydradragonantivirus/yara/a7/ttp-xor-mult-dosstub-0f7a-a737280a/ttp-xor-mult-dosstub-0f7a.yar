rule TTP_XOR_MULT_DOSStub_0f7a {
  strings:
    $key_0f7a = { 5b 12 [2] 2f 0a [2] 68 08 [2] 2f 19 [2] 61 15 [2] 6d 1f [2] 7a 14 [2] 61 5a [2] 5c }

  condition:
    any of them
}