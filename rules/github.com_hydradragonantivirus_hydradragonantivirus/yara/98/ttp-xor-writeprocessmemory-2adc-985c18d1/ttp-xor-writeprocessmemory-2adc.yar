rule TTP_XOR_WriteProcessMemory_2adc {
  strings:
    $key_2adc = { 7d ae [2] 4f 8c [2] 49 b9 [2] 67 b9 [2] 58 a5 }

  condition:
    any of them
}