rule TTP_XOR_MULT_DOSStub_240a {
  strings:
    $key_240a = { 70 62 [2] 04 7a [2] 43 78 [2] 04 69 [2] 4a 65 [2] 46 6f [2] 51 64 [2] 4a 2a [2] 77 }

  condition:
    any of them
}