rule TTP_XOR_MULT_DOSStub_2b41 {
  strings:
    $key_2b41 = { 7f 29 [2] 0b 31 [2] 4c 33 [2] 0b 22 [2] 45 2e [2] 49 24 [2] 5e 2f [2] 45 61 [2] 78 }

  condition:
    any of them
}