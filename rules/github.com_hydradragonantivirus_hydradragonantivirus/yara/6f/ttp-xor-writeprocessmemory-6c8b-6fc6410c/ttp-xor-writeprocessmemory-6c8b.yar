rule TTP_XOR_WriteProcessMemory_6c8b {
  strings:
    $key_6c8b = { 3b f9 [2] 09 db [2] 0f ee [2] 21 ee [2] 1e f2 }

  condition:
    any of them
}