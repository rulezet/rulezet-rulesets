rule TTP_XOR_WriteProcessMemory_3ff3 {
  strings:
    $key_3ff3 = { 68 81 [2] 5a a3 [2] 5c 96 [2] 72 96 [2] 4d 8a }

  condition:
    any of them
}