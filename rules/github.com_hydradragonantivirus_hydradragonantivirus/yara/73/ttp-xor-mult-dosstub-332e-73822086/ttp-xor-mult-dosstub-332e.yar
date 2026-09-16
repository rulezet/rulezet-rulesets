rule TTP_XOR_MULT_DOSStub_332e {
  strings:
    $key_332e = { 67 46 [2] 13 5e [2] 54 5c [2] 13 4d [2] 5d 41 [2] 51 4b [2] 46 40 [2] 5d 0e [2] 60 }

  condition:
    any of them
}