rule TTP_XOR_MULT_DOSStub_2a30 {
  strings:
    $key_2a30 = { 7e 58 [2] 0a 40 [2] 4d 42 [2] 0a 53 [2] 44 5f [2] 48 55 [2] 5f 5e [2] 44 10 [2] 79 }

  condition:
    any of them
}