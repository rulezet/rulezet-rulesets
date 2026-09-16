rule TTP_XOR_WriteProcessMemory_2ca8 {
  strings:
    $key_2ca8 = { 7b da [2] 49 f8 [2] 4f cd [2] 61 cd [2] 5e d1 }

  condition:
    any of them
}