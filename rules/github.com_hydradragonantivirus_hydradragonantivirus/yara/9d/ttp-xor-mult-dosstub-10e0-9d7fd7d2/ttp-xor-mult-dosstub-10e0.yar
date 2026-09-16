rule TTP_XOR_MULT_DOSStub_10e0 {
  strings:
    $key_10e0 = { 44 88 [2] 30 90 [2] 77 92 [2] 30 83 [2] 7e 8f [2] 72 85 [2] 65 8e [2] 7e c0 [2] 43 }

  condition:
    any of them
}