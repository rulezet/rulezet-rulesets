rule TTP_XOR_MULT_DOSStub_542e {
  strings:
    $key_542e = { 00 46 [2] 74 5e [2] 33 5c [2] 74 4d [2] 3a 41 [2] 36 4b [2] 21 40 [2] 3a 0e [2] 07 }

  condition:
    any of them
}