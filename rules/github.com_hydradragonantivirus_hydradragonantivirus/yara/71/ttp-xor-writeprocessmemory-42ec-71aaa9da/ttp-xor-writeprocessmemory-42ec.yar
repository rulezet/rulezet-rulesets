rule TTP_XOR_WriteProcessMemory_42ec {
  strings:
    $key_42ec = { 15 9e [2] 27 bc [2] 21 89 [2] 0f 89 [2] 30 95 }

  condition:
    any of them
}