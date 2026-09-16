rule TTP_XOR_MULT_DOSStub_7b70 {
  strings:
    $key_7b70 = { 2f 18 [2] 5b 00 [2] 1c 02 [2] 5b 13 [2] 15 1f [2] 19 15 [2] 0e 1e [2] 15 50 [2] 28 }

  condition:
    any of them
}