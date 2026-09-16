rule TTP_XOR_MULT_DOSStub_411e {
  strings:
    $key_411e = { 15 76 [2] 61 6e [2] 26 6c [2] 61 7d [2] 2f 71 [2] 23 7b [2] 34 70 [2] 2f 3e [2] 12 }

  condition:
    any of them
}