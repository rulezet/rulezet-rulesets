rule TTP_XOR_WriteProcessMemory_44ec {
  strings:
    $key_44ec = { 13 9e [2] 21 bc [2] 27 89 [2] 09 89 [2] 36 95 }

  condition:
    any of them
}