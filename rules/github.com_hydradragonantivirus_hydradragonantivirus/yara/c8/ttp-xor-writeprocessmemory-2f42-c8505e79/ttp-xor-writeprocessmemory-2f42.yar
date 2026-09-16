rule TTP_XOR_WriteProcessMemory_2f42 {
  strings:
    $key_2f42 = { 78 30 [2] 4a 12 [2] 4c 27 [2] 62 27 [2] 5d 3b }

  condition:
    any of them
}