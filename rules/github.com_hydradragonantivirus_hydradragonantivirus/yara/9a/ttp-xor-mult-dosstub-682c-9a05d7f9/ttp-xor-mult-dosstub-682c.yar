rule TTP_XOR_MULT_DOSStub_682c {
  strings:
    $key_682c = { 3c 44 [2] 48 5c [2] 0f 5e [2] 48 4f [2] 06 43 [2] 0a 49 [2] 1d 42 [2] 06 0c [2] 3b }

  condition:
    any of them
}