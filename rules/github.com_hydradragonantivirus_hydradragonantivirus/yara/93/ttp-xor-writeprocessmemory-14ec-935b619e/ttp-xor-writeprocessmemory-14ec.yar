rule TTP_XOR_WriteProcessMemory_14ec {
  strings:
    $key_14ec = { 43 9e [2] 71 bc [2] 77 89 [2] 59 89 [2] 66 95 }

  condition:
    any of them
}