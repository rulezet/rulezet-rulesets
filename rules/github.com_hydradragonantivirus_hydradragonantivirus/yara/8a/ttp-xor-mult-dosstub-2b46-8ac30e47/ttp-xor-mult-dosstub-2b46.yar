rule TTP_XOR_MULT_DOSStub_2b46 {
  strings:
    $key_2b46 = { 7f 2e [2] 0b 36 [2] 4c 34 [2] 0b 25 [2] 45 29 [2] 49 23 [2] 5e 28 [2] 45 66 [2] 78 }

  condition:
    any of them
}