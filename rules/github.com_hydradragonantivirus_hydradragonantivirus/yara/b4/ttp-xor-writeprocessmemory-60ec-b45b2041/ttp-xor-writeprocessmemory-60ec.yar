rule TTP_XOR_WriteProcessMemory_60ec {
  strings:
    $key_60ec = { 37 9e [2] 05 bc [2] 03 89 [2] 2d 89 [2] 12 95 }

  condition:
    any of them
}