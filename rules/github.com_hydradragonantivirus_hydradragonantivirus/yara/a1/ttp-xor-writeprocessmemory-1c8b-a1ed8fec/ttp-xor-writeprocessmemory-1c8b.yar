rule TTP_XOR_WriteProcessMemory_1c8b {
  strings:
    $key_1c8b = { 4b f9 [2] 79 db [2] 7f ee [2] 51 ee [2] 6e f2 }

  condition:
    any of them
}