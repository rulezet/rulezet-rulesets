rule TTP_XOR_MULT_DOSStub_3b70 {
  strings:
    $key_3b70 = { 6f 18 [2] 1b 00 [2] 5c 02 [2] 1b 13 [2] 55 1f [2] 59 15 [2] 4e 1e [2] 55 50 [2] 68 }

  condition:
    any of them
}