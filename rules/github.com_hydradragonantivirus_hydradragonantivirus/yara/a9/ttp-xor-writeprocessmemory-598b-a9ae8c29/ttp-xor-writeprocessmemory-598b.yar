rule TTP_XOR_WriteProcessMemory_598b {
  strings:
    $key_598b = { 0e f9 [2] 3c db [2] 3a ee [2] 14 ee [2] 2b f2 }

  condition:
    any of them
}