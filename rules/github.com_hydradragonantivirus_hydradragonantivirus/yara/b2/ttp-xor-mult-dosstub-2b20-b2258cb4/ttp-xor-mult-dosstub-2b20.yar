rule TTP_XOR_MULT_DOSStub_2b20 {
  strings:
    $key_2b20 = { 7f 48 [2] 0b 50 [2] 4c 52 [2] 0b 43 [2] 45 4f [2] 49 45 [2] 5e 4e [2] 45 00 [2] 78 }

  condition:
    any of them
}