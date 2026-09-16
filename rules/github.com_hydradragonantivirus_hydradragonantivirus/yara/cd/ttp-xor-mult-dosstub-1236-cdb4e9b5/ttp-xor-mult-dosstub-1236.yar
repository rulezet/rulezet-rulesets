rule TTP_XOR_MULT_DOSStub_1236 {
  strings:
    $key_1236 = { 46 5e [2] 32 46 [2] 75 44 [2] 32 55 [2] 7c 59 [2] 70 53 [2] 67 58 [2] 7c 16 [2] 41 }

  condition:
    any of them
}