rule TTP_XOR_MULT_DOSStub_2b27 {
  strings:
    $key_2b27 = { 7f 4f [2] 0b 57 [2] 4c 55 [2] 0b 44 [2] 45 48 [2] 49 42 [2] 5e 49 [2] 45 07 [2] 78 }

  condition:
    any of them
}