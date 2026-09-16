rule TTP_XOR_MULT_DOSStub_207e {
  strings:
    $key_207e = { 74 16 [2] 00 0e [2] 47 0c [2] 00 1d [2] 4e 11 [2] 42 1b [2] 55 10 [2] 4e 5e [2] 73 }

  condition:
    any of them
}