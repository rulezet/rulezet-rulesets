rule TTP_XOR_MULT_DOSStub_074c {
  strings:
    $key_074c = { 53 24 [2] 27 3c [2] 60 3e [2] 27 2f [2] 69 23 [2] 65 29 [2] 72 22 [2] 69 6c [2] 54 }

  condition:
    any of them
}