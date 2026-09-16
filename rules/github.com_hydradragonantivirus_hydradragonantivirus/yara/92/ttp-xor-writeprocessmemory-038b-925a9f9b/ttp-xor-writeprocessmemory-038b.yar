rule TTP_XOR_WriteProcessMemory_038b {
  strings:
    $key_038b = { 54 f9 [2] 66 db [2] 60 ee [2] 4e ee [2] 71 f2 }

  condition:
    any of them
}