rule TTP_XOR_MULT_DOSStub_2b57 {
  strings:
    $key_2b57 = { 7f 3f [2] 0b 27 [2] 4c 25 [2] 0b 34 [2] 45 38 [2] 49 32 [2] 5e 39 [2] 45 77 [2] 78 }

  condition:
    any of them
}