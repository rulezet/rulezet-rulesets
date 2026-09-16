rule TTP_XOR_MULT_DOSStub_4f0a {
  strings:
    $key_4f0a = { 1b 62 [2] 6f 7a [2] 28 78 [2] 6f 69 [2] 21 65 [2] 2d 6f [2] 3a 64 [2] 21 2a [2] 1c }

  condition:
    any of them
}