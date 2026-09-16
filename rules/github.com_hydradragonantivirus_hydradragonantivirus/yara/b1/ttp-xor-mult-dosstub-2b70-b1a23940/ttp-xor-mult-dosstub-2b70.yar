rule TTP_XOR_MULT_DOSStub_2b70 {
  strings:
    $key_2b70 = { 7f 18 [2] 0b 00 [2] 4c 02 [2] 0b 13 [2] 45 1f [2] 49 15 [2] 5e 1e [2] 45 50 [2] 78 }

  condition:
    any of them
}