rule TTP_XOR_MULT_DOSStub_307d {
  strings:
    $key_307d = { 64 15 [2] 10 0d [2] 57 0f [2] 10 1e [2] 5e 12 [2] 52 18 [2] 45 13 [2] 5e 5d [2] 63 }

  condition:
    any of them
}