rule TTP_XOR_WriteProcessMemory_ec8b {
  strings:
    $key_ec8b = { bb f9 [2] 89 db [2] 8f ee [2] a1 ee [2] 9e f2 }

  condition:
    any of them
}