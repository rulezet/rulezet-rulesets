rule TTP_XOR_MULT_DOSStub_3b57 {
  strings:
    $key_3b57 = { 6f 3f [2] 1b 27 [2] 5c 25 [2] 1b 34 [2] 55 38 [2] 59 32 [2] 4e 39 [2] 55 77 [2] 68 }

  condition:
    any of them
}