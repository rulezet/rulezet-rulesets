rule TTP_XOR_WriteProcessMemory_1371 {
  strings:
    $key_1371 = { 44 03 [2] 76 21 [2] 70 14 [2] 5e 14 [2] 61 08 }

  condition:
    any of them
}