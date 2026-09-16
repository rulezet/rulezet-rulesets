rule TTP_XOR_MULT_DOSStub_317d {
  strings:
    $key_317d = { 65 15 [2] 11 0d [2] 56 0f [2] 11 1e [2] 5f 12 [2] 53 18 [2] 44 13 [2] 5f 5d [2] 62 }

  condition:
    any of them
}