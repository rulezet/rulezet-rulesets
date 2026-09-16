rule TTP_XOR_MULT_DOSStub_562c {
  strings:
    $key_562c = { 02 44 [2] 76 5c [2] 31 5e [2] 76 4f [2] 38 43 [2] 34 49 [2] 23 42 [2] 38 0c [2] 05 }

  condition:
    any of them
}