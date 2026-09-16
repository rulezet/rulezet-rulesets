rule TTP_XOR_MULT_DOSStub_2b40 {
  strings:
    $key_2b40 = { 7f 28 [2] 0b 30 [2] 4c 32 [2] 0b 23 [2] 45 2f [2] 49 25 [2] 5e 2e [2] 45 60 [2] 78 }

  condition:
    any of them
}