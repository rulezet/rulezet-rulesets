rule TTP_XOR_MULT_DOSStub_003d {
  strings:
    $key_003d = { 54 55 [2] 20 4d [2] 67 4f [2] 20 5e [2] 6e 52 [2] 62 58 [2] 75 53 [2] 6e 1d [2] 53 }

  condition:
    any of them
}