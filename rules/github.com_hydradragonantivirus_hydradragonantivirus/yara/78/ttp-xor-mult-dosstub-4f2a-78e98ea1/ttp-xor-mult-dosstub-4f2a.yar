rule TTP_XOR_MULT_DOSStub_4f2a {
  strings:
    $key_4f2a = { 1b 42 [2] 6f 5a [2] 28 58 [2] 6f 49 [2] 21 45 [2] 2d 4f [2] 3a 44 [2] 21 0a [2] 1c }

  condition:
    any of them
}