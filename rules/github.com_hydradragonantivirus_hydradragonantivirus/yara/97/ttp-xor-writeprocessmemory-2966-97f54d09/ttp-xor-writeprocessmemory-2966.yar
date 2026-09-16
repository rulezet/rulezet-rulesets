rule TTP_XOR_WriteProcessMemory_2966 {
  strings:
    $key_2966 = { 7e 14 [2] 4c 36 [2] 4a 03 [2] 64 03 [2] 5b 1f }

  condition:
    any of them
}