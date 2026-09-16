rule TTP_XOR_MULT_DOSStub_127d {
  strings:
    $key_127d = { 46 15 [2] 32 0d [2] 75 0f [2] 32 1e [2] 7c 12 [2] 70 18 [2] 67 13 [2] 7c 5d [2] 41 }

  condition:
    any of them
}