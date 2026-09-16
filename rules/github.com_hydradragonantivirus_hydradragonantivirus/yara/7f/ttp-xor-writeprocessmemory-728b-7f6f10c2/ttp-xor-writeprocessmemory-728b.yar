rule TTP_XOR_WriteProcessMemory_728b {
  strings:
    $key_728b = { 25 f9 [2] 17 db [2] 11 ee [2] 3f ee [2] 00 f2 }

  condition:
    any of them
}