rule TTP_XOR_WriteProcessMemory_7756 {
  strings:
    $key_7756 = { 20 24 [2] 12 06 [2] 14 33 [2] 3a 33 [2] 05 2f }

  condition:
    any of them
}