rule TTP_XOR_MULT_DOSStub_1a3c {
  strings:
    $key_1a3c = { 4e 54 [2] 3a 4c [2] 7d 4e [2] 3a 5f [2] 74 53 [2] 78 59 [2] 6f 52 [2] 74 1c [2] 49 }

  condition:
    any of them
}