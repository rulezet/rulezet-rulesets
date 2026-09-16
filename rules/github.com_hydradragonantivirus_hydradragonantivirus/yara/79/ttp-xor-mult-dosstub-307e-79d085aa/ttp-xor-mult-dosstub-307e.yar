rule TTP_XOR_MULT_DOSStub_307e {
  strings:
    $key_307e = { 64 16 [2] 10 0e [2] 57 0c [2] 10 1d [2] 5e 11 [2] 52 1b [2] 45 10 [2] 5e 5e [2] 63 }

  condition:
    any of them
}