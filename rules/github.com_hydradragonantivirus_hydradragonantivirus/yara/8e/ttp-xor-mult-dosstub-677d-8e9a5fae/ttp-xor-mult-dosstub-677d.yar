rule TTP_XOR_MULT_DOSStub_677d {
  strings:
    $key_677d = { 33 15 [2] 47 0d [2] 00 0f [2] 47 1e [2] 09 12 [2] 05 18 [2] 12 13 [2] 09 5d [2] 34 }

  condition:
    any of them
}