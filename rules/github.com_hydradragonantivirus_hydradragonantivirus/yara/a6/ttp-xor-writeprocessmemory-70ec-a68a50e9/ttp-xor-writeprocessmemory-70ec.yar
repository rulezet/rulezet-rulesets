rule TTP_XOR_WriteProcessMemory_70ec {
  strings:
    $key_70ec = { 27 9e [2] 15 bc [2] 13 89 [2] 3d 89 [2] 02 95 }

  condition:
    any of them
}