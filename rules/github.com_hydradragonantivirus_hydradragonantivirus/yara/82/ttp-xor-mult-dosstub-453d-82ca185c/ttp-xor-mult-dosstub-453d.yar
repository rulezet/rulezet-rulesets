rule TTP_XOR_MULT_DOSStub_453d {
  strings:
    $key_453d = { 11 55 [2] 65 4d [2] 22 4f [2] 65 5e [2] 2b 52 [2] 27 58 [2] 30 53 [2] 2b 1d [2] 16 }

  condition:
    any of them
}