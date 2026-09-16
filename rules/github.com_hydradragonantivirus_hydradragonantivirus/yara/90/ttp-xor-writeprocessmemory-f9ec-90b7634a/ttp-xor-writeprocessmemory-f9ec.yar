rule TTP_XOR_WriteProcessMemory_f9ec {
  strings:
    $key_f9ec = { ae 9e [2] 9c bc [2] 9a 89 [2] b4 89 [2] 8b 95 }

  condition:
    any of them
}