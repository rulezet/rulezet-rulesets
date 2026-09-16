rule TTP_XOR_WriteProcessMemory_39ec {
  strings:
    $key_39ec = { 6e 9e [2] 5c bc [2] 5a 89 [2] 74 89 [2] 4b 95 }

  condition:
    any of them
}