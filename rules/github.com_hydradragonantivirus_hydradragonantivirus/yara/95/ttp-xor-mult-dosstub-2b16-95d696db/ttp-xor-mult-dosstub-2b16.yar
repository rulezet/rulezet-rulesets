rule TTP_XOR_MULT_DOSStub_2b16 {
  strings:
    $key_2b16 = { 7f 7e [2] 0b 66 [2] 4c 64 [2] 0b 75 [2] 45 79 [2] 49 73 [2] 5e 78 [2] 45 36 [2] 78 }

  condition:
    any of them
}