rule TTP_XOR_WriteProcessMemory_1fec {
  strings:
    $key_1fec = { 48 9e [2] 7a bc [2] 7c 89 [2] 52 89 [2] 6d 95 }

  condition:
    any of them
}