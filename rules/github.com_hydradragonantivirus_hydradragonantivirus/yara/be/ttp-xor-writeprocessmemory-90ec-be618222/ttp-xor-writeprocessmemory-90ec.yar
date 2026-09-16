rule TTP_XOR_WriteProcessMemory_90ec {
  strings:
    $key_90ec = { c7 9e [2] f5 bc [2] f3 89 [2] dd 89 [2] e2 95 }

  condition:
    any of them
}