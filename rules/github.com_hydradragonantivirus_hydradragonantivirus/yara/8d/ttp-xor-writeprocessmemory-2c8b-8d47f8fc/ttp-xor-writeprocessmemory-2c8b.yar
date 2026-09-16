rule TTP_XOR_WriteProcessMemory_2c8b {
  strings:
    $key_2c8b = { 7b f9 [2] 49 db [2] 4f ee [2] 61 ee [2] 5e f2 }

  condition:
    any of them
}