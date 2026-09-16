rule TTP_XOR_MULT_DOSStub_567d {
  strings:
    $key_567d = { 02 15 [2] 76 0d [2] 31 0f [2] 76 1e [2] 38 12 [2] 34 18 [2] 23 13 [2] 38 5d [2] 05 }

  condition:
    any of them
}