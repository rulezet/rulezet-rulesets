rule TTP_XOR_MULT_DOSStub_773d {
  strings:
    $key_773d = { 23 55 [2] 57 4d [2] 10 4f [2] 57 5e [2] 19 52 [2] 15 58 [2] 02 53 [2] 19 1d [2] 24 }

  condition:
    any of them
}