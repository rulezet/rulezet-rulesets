rule TTP_XOR_MULT_DOSStub_6001 {
  strings:
    $key_6001 = { 34 69 [2] 40 71 [2] 07 73 [2] 40 62 [2] 0e 6e [2] 02 64 [2] 15 6f [2] 0e 21 [2] 33 }

  condition:
    any of them
}