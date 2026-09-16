rule TTP_XOR_WriteProcessMemory_64ec {
  strings:
    $key_64ec = { 33 9e [2] 01 bc [2] 07 89 [2] 29 89 [2] 16 95 }

  condition:
    any of them
}