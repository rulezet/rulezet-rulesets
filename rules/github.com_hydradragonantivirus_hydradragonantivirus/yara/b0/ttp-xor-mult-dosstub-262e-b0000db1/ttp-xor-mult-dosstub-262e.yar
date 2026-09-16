rule TTP_XOR_MULT_DOSStub_262e {
  strings:
    $key_262e = { 72 46 [2] 06 5e [2] 41 5c [2] 06 4d [2] 48 41 [2] 44 4b [2] 53 40 [2] 48 0e [2] 75 }

  condition:
    any of them
}