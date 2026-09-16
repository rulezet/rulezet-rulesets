rule TTP_XOR_MULT_DOSStub_7011 {
  strings:
    $key_7011 = { 24 79 [2] 50 61 [2] 17 63 [2] 50 72 [2] 1e 7e [2] 12 74 [2] 05 7f [2] 1e 31 [2] 23 }

  condition:
    any of them
}