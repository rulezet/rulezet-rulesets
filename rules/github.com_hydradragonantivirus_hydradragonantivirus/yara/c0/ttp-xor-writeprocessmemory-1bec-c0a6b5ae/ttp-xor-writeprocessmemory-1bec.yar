rule TTP_XOR_WriteProcessMemory_1bec {
  strings:
    $key_1bec = { 4c 9e [2] 7e bc [2] 78 89 [2] 56 89 [2] 69 95 }

  condition:
    any of them
}