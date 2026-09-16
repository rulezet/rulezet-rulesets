rule TTP_XOR_WriteProcessMemory_2b8b {
  strings:
    $key_2b8b = { 7c f9 [2] 4e db [2] 48 ee [2] 66 ee [2] 59 f2 }

  condition:
    any of them
}