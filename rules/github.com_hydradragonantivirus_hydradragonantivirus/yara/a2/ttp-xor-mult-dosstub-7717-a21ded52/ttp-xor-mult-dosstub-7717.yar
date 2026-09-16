rule TTP_XOR_MULT_DOSStub_7717 {
  strings:
    $key_7717 = { 23 7f [2] 57 67 [2] 10 65 [2] 57 74 [2] 19 78 [2] 15 72 [2] 02 79 [2] 19 37 [2] 24 }

  condition:
    any of them
}