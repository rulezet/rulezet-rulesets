rule TTP_XOR_WriteProcessMemory_5cbe {
  strings:
    $key_5cbe = { 0b cc [2] 39 ee [2] 3f db [2] 11 db [2] 2e c7 }

  condition:
    any of them
}