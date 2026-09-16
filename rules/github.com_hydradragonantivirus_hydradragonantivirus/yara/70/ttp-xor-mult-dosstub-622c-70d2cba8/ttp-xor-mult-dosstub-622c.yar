rule TTP_XOR_MULT_DOSStub_622c {
  strings:
    $key_622c = { 36 44 [2] 42 5c [2] 05 5e [2] 42 4f [2] 0c 43 [2] 00 49 [2] 17 42 [2] 0c 0c [2] 31 }

  condition:
    any of them
}