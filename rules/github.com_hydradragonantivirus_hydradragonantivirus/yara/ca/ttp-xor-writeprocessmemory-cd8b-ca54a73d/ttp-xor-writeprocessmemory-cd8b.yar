rule TTP_XOR_WriteProcessMemory_cd8b {
  strings:
    $key_cd8b = { 9a f9 [2] a8 db [2] ae ee [2] 80 ee [2] bf f2 }

  condition:
    any of them
}