rule TTP_XOR_MULT_DOSStub_473d {
  strings:
    $key_473d = { 13 55 [2] 67 4d [2] 20 4f [2] 67 5e [2] 29 52 [2] 25 58 [2] 32 53 [2] 29 1d [2] 14 }

  condition:
    any of them
}