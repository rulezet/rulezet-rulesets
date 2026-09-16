rule TTP_XOR_MULT_DOSStub_244e {
  strings:
    $key_244e = { 70 26 [2] 04 3e [2] 43 3c [2] 04 2d [2] 4a 21 [2] 46 2b [2] 51 20 [2] 4a 6e [2] 77 }

  condition:
    any of them
}