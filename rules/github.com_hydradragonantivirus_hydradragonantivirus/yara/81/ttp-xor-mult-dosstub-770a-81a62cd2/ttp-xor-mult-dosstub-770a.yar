rule TTP_XOR_MULT_DOSStub_770a {
  strings:
    $key_770a = { 23 62 [2] 57 7a [2] 10 78 [2] 57 69 [2] 19 65 [2] 15 6f [2] 02 64 [2] 19 2a [2] 24 }

  condition:
    any of them
}