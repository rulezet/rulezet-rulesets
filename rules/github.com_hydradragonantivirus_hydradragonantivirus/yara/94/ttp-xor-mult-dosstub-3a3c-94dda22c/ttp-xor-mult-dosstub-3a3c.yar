rule TTP_XOR_MULT_DOSStub_3a3c {
  strings:
    $key_3a3c = { 6e 54 [2] 1a 4c [2] 5d 4e [2] 1a 5f [2] 54 53 [2] 58 59 [2] 4f 52 [2] 54 1c [2] 69 }

  condition:
    any of them
}