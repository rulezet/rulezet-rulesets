rule TTP_XOR_WriteProcessMemory_5c8b {
  strings:
    $key_5c8b = { 0b f9 [2] 39 db [2] 3f ee [2] 11 ee [2] 2e f2 }

  condition:
    any of them
}