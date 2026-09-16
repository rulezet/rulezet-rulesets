rule TTP_XOR_MULT_DOSStub_150a {
  strings:
    $key_150a = { 41 62 [2] 35 7a [2] 72 78 [2] 35 69 [2] 7b 65 [2] 77 6f [2] 60 64 [2] 7b 2a [2] 46 }

  condition:
    any of them
}