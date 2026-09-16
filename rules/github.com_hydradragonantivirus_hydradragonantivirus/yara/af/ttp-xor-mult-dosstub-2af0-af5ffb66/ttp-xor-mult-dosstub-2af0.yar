rule TTP_XOR_MULT_DOSStub_2af0 {
  strings:
    $key_2af0 = { 7e 98 [2] 0a 80 [2] 4d 82 [2] 0a 93 [2] 44 9f [2] 48 95 [2] 5f 9e [2] 44 d0 [2] 79 }

  condition:
    any of them
}