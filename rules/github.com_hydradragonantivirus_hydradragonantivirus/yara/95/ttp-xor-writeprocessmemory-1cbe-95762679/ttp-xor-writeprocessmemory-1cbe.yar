rule TTP_XOR_WriteProcessMemory_1cbe {
  strings:
    $key_1cbe = { 4b cc [2] 79 ee [2] 7f db [2] 51 db [2] 6e c7 }

  condition:
    any of them
}