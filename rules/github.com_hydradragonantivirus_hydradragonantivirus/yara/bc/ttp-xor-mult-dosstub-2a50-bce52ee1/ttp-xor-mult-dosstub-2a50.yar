rule TTP_XOR_MULT_DOSStub_2a50 {
  strings:
    $key_2a50 = { 7e 38 [2] 0a 20 [2] 4d 22 [2] 0a 33 [2] 44 3f [2] 48 35 [2] 5f 3e [2] 44 70 [2] 79 }

  condition:
    any of them
}