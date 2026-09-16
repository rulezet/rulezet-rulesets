rule TTP_XOR_MULT_DOSStub_670b {
  strings:
    $key_670b = { 33 63 [2] 47 7b [2] 00 79 [2] 47 68 [2] 09 64 [2] 05 6e [2] 12 65 [2] 09 2b [2] 34 }

  condition:
    any of them
}