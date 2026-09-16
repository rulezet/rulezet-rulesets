rule TTP_XOR_MULT_DOSStub_7a2d {
  strings:
    $key_7a2d = { 2e 45 [2] 5a 5d [2] 1d 5f [2] 5a 4e [2] 14 42 [2] 18 48 [2] 0f 43 [2] 14 0d [2] 29 }

  condition:
    any of them
}