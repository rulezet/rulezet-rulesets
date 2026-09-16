rule TTP_XOR_MULT_DOSStub_4f7a {
  strings:
    $key_4f7a = { 1b 12 [2] 6f 0a [2] 28 08 [2] 6f 19 [2] 21 15 [2] 2d 1f [2] 3a 14 [2] 21 5a [2] 1c }

  condition:
    any of them
}