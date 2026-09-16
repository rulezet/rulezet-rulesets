rule TTP_XOR_WriteProcessMemory_50ec {
  strings:
    $key_50ec = { 07 9e [2] 35 bc [2] 33 89 [2] 1d 89 [2] 22 95 }

  condition:
    any of them
}