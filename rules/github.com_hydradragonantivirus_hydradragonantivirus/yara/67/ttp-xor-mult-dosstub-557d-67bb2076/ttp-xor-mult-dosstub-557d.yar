rule TTP_XOR_MULT_DOSStub_557d {
  strings:
    $key_557d = { 01 15 [2] 75 0d [2] 32 0f [2] 75 1e [2] 3b 12 [2] 37 18 [2] 20 13 [2] 3b 5d [2] 06 }

  condition:
    any of them
}