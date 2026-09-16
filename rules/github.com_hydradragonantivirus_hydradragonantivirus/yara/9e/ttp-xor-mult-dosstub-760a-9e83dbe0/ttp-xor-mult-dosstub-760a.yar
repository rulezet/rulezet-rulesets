rule TTP_XOR_MULT_DOSStub_760a {
  strings:
    $key_760a = { 22 62 [2] 56 7a [2] 11 78 [2] 56 69 [2] 18 65 [2] 14 6f [2] 03 64 [2] 18 2a [2] 25 }

  condition:
    any of them
}