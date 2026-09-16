rule TTP_XOR_MULT_DOSStub_117e {
  strings:
    $key_117e = { 45 16 [2] 31 0e [2] 76 0c [2] 31 1d [2] 7f 11 [2] 73 1b [2] 64 10 [2] 7f 5e [2] 42 }

  condition:
    any of them
}