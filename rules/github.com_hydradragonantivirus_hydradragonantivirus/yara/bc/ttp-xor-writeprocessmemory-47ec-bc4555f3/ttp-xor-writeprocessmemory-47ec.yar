rule TTP_XOR_WriteProcessMemory_47ec {
  strings:
    $key_47ec = { 10 9e [2] 22 bc [2] 24 89 [2] 0a 89 [2] 35 95 }

  condition:
    any of them
}