rule TTP_XOR_MULT_DOSStub_167e {
  strings:
    $key_167e = { 42 16 [2] 36 0e [2] 71 0c [2] 36 1d [2] 78 11 [2] 74 1b [2] 63 10 [2] 78 5e [2] 45 }

  condition:
    any of them
}