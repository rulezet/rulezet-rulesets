rule TTP_XOR_MULT_DOSStub_3b47 {
  strings:
    $key_3b47 = { 6f 2f [2] 1b 37 [2] 5c 35 [2] 1b 24 [2] 55 28 [2] 59 22 [2] 4e 29 [2] 55 67 [2] 68 }

  condition:
    any of them
}