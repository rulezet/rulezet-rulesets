rule TTP_XOR_MULT_DOSStub_5601 {
  strings:
    $key_5601 = { 02 69 [2] 76 71 [2] 31 73 [2] 76 62 [2] 38 6e [2] 34 64 [2] 23 6f [2] 38 21 [2] 05 }

  condition:
    any of them
}