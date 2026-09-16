rule TTP_XOR_MULT_DOSStub_312c {
  strings:
    $key_312c = { 65 44 [2] 11 5c [2] 56 5e [2] 11 4f [2] 5f 43 [2] 53 49 [2] 44 42 [2] 5f 0c [2] 62 }

  condition:
    any of them
}