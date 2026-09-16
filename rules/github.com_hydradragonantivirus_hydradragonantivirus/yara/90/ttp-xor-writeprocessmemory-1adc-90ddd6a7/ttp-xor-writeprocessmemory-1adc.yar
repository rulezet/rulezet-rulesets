rule TTP_XOR_WriteProcessMemory_1adc {
  strings:
    $key_1adc = { 4d ae [2] 7f 8c [2] 79 b9 [2] 57 b9 [2] 68 a5 }

  condition:
    any of them
}