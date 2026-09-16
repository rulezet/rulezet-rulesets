rule TTP_XOR_MULT_DOSStub_7cf9 {
  strings:
    $key_7cf9 = { 28 91 [2] 5c 89 [2] 1b 8b [2] 5c 9a [2] 12 96 [2] 1e 9c [2] 09 97 [2] 12 d9 [2] 2f }

  condition:
    any of them
}