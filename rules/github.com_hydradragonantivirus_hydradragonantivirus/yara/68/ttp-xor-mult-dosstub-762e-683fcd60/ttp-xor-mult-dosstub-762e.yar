rule TTP_XOR_MULT_DOSStub_762e {
  strings:
    $key_762e = { 22 46 [2] 56 5e [2] 11 5c [2] 56 4d [2] 18 41 [2] 14 4b [2] 03 40 [2] 18 0e [2] 25 }

  condition:
    any of them
}