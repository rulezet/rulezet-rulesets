rule TTP_XOR_MULT_DOSStub_142e {
  strings:
    $key_142e = { 40 46 [2] 34 5e [2] 73 5c [2] 34 4d [2] 7a 41 [2] 76 4b [2] 61 40 [2] 7a 0e [2] 47 }

  condition:
    any of them
}