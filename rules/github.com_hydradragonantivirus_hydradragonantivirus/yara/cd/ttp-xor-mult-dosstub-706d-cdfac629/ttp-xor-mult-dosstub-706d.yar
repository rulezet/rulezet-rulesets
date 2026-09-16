rule TTP_XOR_MULT_DOSStub_706d {
  strings:
    $key_706d = { 24 05 [2] 50 1d [2] 17 1f [2] 50 0e [2] 1e 02 [2] 12 08 [2] 05 03 [2] 1e 4d [2] 23 }

  condition:
    any of them
}