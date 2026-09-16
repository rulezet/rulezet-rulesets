rule TTP_XOR_WriteProcessMemory_19ec {
  strings:
    $key_19ec = { 4e 9e [2] 7c bc [2] 7a 89 [2] 54 89 [2] 6b 95 }

  condition:
    any of them
}