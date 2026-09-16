rule TTP_XOR_WriteProcessMemory_6adc {
  strings:
    $key_6adc = { 3d ae [2] 0f 8c [2] 09 b9 [2] 27 b9 [2] 18 a5 }

  condition:
    any of them
}