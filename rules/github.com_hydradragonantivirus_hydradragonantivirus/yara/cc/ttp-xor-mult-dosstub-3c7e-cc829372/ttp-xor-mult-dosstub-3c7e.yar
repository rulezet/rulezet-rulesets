rule TTP_XOR_MULT_DOSStub_3c7e {
  strings:
    $key_3c7e = { 68 16 [2] 1c 0e [2] 5b 0c [2] 1c 1d [2] 52 11 [2] 5e 1b [2] 49 10 [2] 52 5e [2] 6f }

  condition:
    any of them
}