rule TTP_XOR_MULT_DOSStub_2a21 {
  strings:
    $key_2a21 = { 7e 49 [2] 0a 51 [2] 4d 53 [2] 0a 42 [2] 44 4e [2] 48 44 [2] 5f 4f [2] 44 01 [2] 79 }

  condition:
    any of them
}