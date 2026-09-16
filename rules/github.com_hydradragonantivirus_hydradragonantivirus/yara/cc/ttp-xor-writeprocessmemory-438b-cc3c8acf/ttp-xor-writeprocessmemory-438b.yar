rule TTP_XOR_WriteProcessMemory_438b {
  strings:
    $key_438b = { 14 f9 [2] 26 db [2] 20 ee [2] 0e ee [2] 31 f2 }

  condition:
    any of them
}