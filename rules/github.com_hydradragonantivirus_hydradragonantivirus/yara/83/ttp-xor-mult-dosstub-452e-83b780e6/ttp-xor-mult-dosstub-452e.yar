rule TTP_XOR_MULT_DOSStub_452e {
  strings:
    $key_452e = { 11 46 [2] 65 5e [2] 22 5c [2] 65 4d [2] 2b 41 [2] 27 4b [2] 30 40 [2] 2b 0e [2] 16 }

  condition:
    any of them
}