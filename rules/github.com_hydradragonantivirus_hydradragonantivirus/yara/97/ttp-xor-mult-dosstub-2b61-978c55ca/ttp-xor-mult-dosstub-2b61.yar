rule TTP_XOR_MULT_DOSStub_2b61 {
  strings:
    $key_2b61 = { 7f 09 [2] 0b 11 [2] 4c 13 [2] 0b 02 [2] 45 0e [2] 49 04 [2] 5e 0f [2] 45 41 [2] 78 }

  condition:
    any of them
}