rule TTP_XOR_MULT_DOSStub_562e {
  strings:
    $key_562e = { 02 46 [2] 76 5e [2] 31 5c [2] 76 4d [2] 38 41 [2] 34 4b [2] 23 40 [2] 38 0e [2] 05 }

  condition:
    any of them
}