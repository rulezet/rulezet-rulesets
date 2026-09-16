rule TTP_XOR_WriteProcessMemory_3ca8 {
  strings:
    $key_3ca8 = { 6b da [2] 59 f8 [2] 5f cd [2] 71 cd [2] 4e d1 }

  condition:
    any of them
}