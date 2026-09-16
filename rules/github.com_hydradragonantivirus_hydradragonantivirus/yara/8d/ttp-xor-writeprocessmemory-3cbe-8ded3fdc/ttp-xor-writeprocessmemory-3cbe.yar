rule TTP_XOR_WriteProcessMemory_3cbe {
  strings:
    $key_3cbe = { 6b cc [2] 59 ee [2] 5f db [2] 71 db [2] 4e c7 }

  condition:
    any of them
}