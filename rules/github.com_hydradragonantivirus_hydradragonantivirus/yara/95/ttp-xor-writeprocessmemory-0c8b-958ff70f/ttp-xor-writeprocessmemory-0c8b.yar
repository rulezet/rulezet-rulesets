rule TTP_XOR_WriteProcessMemory_0c8b {
  strings:
    $key_0c8b = { 5b f9 [2] 69 db [2] 6f ee [2] 41 ee [2] 7e f2 }

  condition:
    any of them
}