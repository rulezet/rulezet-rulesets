rule TTP_XOR_MULT_DOSStub_752d {
  strings:
    $key_752d = { 21 45 [2] 55 5d [2] 12 5f [2] 55 4e [2] 1b 42 [2] 17 48 [2] 00 43 [2] 1b 0d [2] 26 }

  condition:
    any of them
}