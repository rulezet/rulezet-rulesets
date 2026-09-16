rule TTP_XOR_WriteProcessMemory_608b {
  strings:
    $key_608b = { 37 f9 [2] 05 db [2] 03 ee [2] 2d ee [2] 12 f2 }

  condition:
    any of them
}