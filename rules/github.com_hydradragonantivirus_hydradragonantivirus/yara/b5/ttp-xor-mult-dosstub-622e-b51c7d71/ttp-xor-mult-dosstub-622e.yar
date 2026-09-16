rule TTP_XOR_MULT_DOSStub_622e {
  strings:
    $key_622e = { 36 46 [2] 42 5e [2] 05 5c [2] 42 4d [2] 0c 41 [2] 00 4b [2] 17 40 [2] 0c 0e [2] 31 }

  condition:
    any of them
}