rule TTP_XOR_MULT_DOSStub_151a {
  strings:
    $key_151a = { 41 72 [2] 35 6a [2] 72 68 [2] 35 79 [2] 7b 75 [2] 77 7f [2] 60 74 [2] 7b 3a [2] 46 }

  condition:
    any of them
}