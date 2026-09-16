rule TTP_XOR_MULT_DOSStub_2a0a {
  strings:
    $key_2a0a = { 7e 62 [2] 0a 7a [2] 4d 78 [2] 0a 69 [2] 44 65 [2] 48 6f [2] 5f 64 [2] 44 2a [2] 79 }

  condition:
    any of them
}