rule TTP_XOR_MULT_DOSStub_2b11 {
  strings:
    $key_2b11 = { 7f 79 [2] 0b 61 [2] 4c 63 [2] 0b 72 [2] 45 7e [2] 49 74 [2] 5e 7f [2] 45 31 [2] 78 }

  condition:
    any of them
}