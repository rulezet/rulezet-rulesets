rule TTP_XOR_MULT_DOSStub_432e {
  strings:
    $key_432e = { 17 46 [2] 63 5e [2] 24 5c [2] 63 4d [2] 2d 41 [2] 21 4b [2] 36 40 [2] 2d 0e [2] 10 }

  condition:
    any of them
}