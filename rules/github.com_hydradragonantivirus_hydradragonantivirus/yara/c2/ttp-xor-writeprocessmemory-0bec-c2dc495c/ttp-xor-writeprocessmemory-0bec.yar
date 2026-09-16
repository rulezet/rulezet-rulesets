rule TTP_XOR_WriteProcessMemory_0bec {
  strings:
    $key_0bec = { 5c 9e [2] 6e bc [2] 68 89 [2] 46 89 [2] 79 95 }

  condition:
    any of them
}