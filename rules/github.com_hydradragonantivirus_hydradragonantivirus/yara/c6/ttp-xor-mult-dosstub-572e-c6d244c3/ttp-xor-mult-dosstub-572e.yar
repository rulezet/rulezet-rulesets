rule TTP_XOR_MULT_DOSStub_572e {
  strings:
    $key_572e = { 03 46 [2] 77 5e [2] 30 5c [2] 77 4d [2] 39 41 [2] 35 4b [2] 22 40 [2] 39 0e [2] 04 }

  condition:
    any of them
}