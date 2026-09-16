rule TTP_XOR_MULT_DOSStub_446d {
  strings:
    $key_446d = { 10 05 [2] 64 1d [2] 23 1f [2] 64 0e [2] 2a 02 [2] 26 08 [2] 31 03 [2] 2a 4d [2] 17 }

  condition:
    any of them
}