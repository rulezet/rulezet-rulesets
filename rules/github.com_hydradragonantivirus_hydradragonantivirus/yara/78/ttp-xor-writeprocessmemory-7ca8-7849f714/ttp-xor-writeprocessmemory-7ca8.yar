rule TTP_XOR_WriteProcessMemory_7ca8 {
  strings:
    $key_7ca8 = { 2b da [2] 19 f8 [2] 1f cd [2] 31 cd [2] 0e d1 }

  condition:
    any of them
}