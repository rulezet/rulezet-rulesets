rule TTP_XOR_WriteProcessMemory_2ff3 {
  strings:
    $key_2ff3 = { 78 81 [2] 4a a3 [2] 4c 96 [2] 62 96 [2] 5d 8a }

  condition:
    any of them
}