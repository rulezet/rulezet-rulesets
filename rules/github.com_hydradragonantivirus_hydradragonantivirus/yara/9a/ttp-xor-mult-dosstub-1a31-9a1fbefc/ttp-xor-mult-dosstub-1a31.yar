rule TTP_XOR_MULT_DOSStub_1a31 {
  strings:
    $key_1a31 = { 4e 59 [2] 3a 41 [2] 7d 43 [2] 3a 52 [2] 74 5e [2] 78 54 [2] 6f 5f [2] 74 11 [2] 49 }

  condition:
    any of them
}