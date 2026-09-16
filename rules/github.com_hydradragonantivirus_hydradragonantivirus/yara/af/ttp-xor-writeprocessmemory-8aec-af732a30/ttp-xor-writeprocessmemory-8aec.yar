rule TTP_XOR_WriteProcessMemory_8aec {
  strings:
    $key_8aec = { dd 9e [2] ef bc [2] e9 89 [2] c7 89 [2] f8 95 }

  condition:
    any of them
}