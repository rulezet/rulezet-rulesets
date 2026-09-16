rule TTP_XOR_MULT_DOSStub_487e {
  strings:
    $key_487e = { 1c 16 [2] 68 0e [2] 2f 0c [2] 68 1d [2] 26 11 [2] 2a 1b [2] 3d 10 [2] 26 5e [2] 1b }

  condition:
    any of them
}