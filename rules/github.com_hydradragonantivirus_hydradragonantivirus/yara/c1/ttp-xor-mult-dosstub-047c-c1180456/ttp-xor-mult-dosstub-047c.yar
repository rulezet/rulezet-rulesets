rule TTP_XOR_MULT_DOSStub_047c {
  strings:
    $key_047c = { 50 14 [2] 24 0c [2] 63 0e [2] 24 1f [2] 6a 13 [2] 66 19 [2] 71 12 [2] 6a 5c [2] 57 }

  condition:
    any of them
}