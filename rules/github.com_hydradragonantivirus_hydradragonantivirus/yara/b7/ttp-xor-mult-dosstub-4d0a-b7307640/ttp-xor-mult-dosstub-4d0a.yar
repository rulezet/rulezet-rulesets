rule TTP_XOR_MULT_DOSStub_4d0a {
  strings:
    $key_4d0a = { 19 62 [2] 6d 7a [2] 2a 78 [2] 6d 69 [2] 23 65 [2] 2f 6f [2] 38 64 [2] 23 2a [2] 1e }

  condition:
    any of them
}