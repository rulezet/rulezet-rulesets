rule TTP_XOR_MULT_DOSStub_1216 {
  strings:
    $key_1216 = { 46 7e [2] 32 66 [2] 75 64 [2] 32 75 [2] 7c 79 [2] 70 73 [2] 67 78 [2] 7c 36 [2] 41 }

  condition:
    any of them
}