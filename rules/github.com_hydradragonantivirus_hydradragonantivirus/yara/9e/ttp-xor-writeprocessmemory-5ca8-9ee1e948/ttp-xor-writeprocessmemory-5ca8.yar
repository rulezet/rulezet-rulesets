rule TTP_XOR_WriteProcessMemory_5ca8 {
  strings:
    $key_5ca8 = { 0b da [2] 39 f8 [2] 3f cd [2] 11 cd [2] 2e d1 }

  condition:
    any of them
}