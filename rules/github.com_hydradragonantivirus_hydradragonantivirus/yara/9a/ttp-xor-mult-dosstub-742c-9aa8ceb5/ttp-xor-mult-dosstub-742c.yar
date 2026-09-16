rule TTP_XOR_MULT_DOSStub_742c {
  strings:
    $key_742c = { 20 44 [2] 54 5c [2] 13 5e [2] 54 4f [2] 1a 43 [2] 16 49 [2] 01 42 [2] 1a 0c [2] 27 }

  condition:
    any of them
}