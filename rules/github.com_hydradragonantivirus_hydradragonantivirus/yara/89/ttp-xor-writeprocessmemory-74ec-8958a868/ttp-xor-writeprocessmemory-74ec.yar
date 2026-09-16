rule TTP_XOR_WriteProcessMemory_74ec {
  strings:
    $key_74ec = { 23 9e [2] 11 bc [2] 17 89 [2] 39 89 [2] 06 95 }

  condition:
    any of them
}