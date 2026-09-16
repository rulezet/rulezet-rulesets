rule TTP_XOR_MULT_DOSStub_340a {
  strings:
    $key_340a = { 60 62 [2] 14 7a [2] 53 78 [2] 14 69 [2] 5a 65 [2] 56 6f [2] 41 64 [2] 5a 2a [2] 67 }

  condition:
    any of them
}