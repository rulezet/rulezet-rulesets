rule TTP_XOR_MULT_DOSStub_680a {
  strings:
    $key_680a = { 3c 62 [2] 48 7a [2] 0f 78 [2] 48 69 [2] 06 65 [2] 0a 6f [2] 1d 64 [2] 06 2a [2] 3b }

  condition:
    any of them
}