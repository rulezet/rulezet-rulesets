rule TTP_XOR_MULT_DOSStub_317e {
  strings:
    $key_317e = { 65 16 [2] 11 0e [2] 56 0c [2] 11 1d [2] 5f 11 [2] 53 1b [2] 44 10 [2] 5f 5e [2] 62 }

  condition:
    any of them
}