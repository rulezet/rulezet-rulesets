rule TTP_XOR_MULT_DOSStub_522e {
  strings:
    $key_522e = { 06 46 [2] 72 5e [2] 35 5c [2] 72 4d [2] 3c 41 [2] 30 4b [2] 27 40 [2] 3c 0e [2] 01 }

  condition:
    any of them
}