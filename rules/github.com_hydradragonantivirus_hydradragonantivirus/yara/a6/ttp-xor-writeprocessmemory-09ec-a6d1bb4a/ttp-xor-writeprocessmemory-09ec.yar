rule TTP_XOR_WriteProcessMemory_09ec {
  strings:
    $key_09ec = { 5e 9e [2] 6c bc [2] 6a 89 [2] 44 89 [2] 7b 95 }

  condition:
    any of them
}