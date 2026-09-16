rule TTP_XOR_MULT_DOSStub_2a31 {
  strings:
    $key_2a31 = { 7e 59 [2] 0a 41 [2] 4d 43 [2] 0a 52 [2] 44 5e [2] 48 54 [2] 5f 5f [2] 44 11 [2] 79 }

  condition:
    any of them
}