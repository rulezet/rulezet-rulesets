rule TTP_XOR_WriteProcessMemory_0273 {
  strings:
    $key_0273 = { 55 01 [2] 67 23 [2] 61 16 [2] 4f 16 [2] 70 0a }

  condition:
    any of them
}