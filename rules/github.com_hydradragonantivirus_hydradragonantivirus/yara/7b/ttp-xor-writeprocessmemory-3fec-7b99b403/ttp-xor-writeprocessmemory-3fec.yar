rule TTP_XOR_WriteProcessMemory_3fec {
  strings:
    $key_3fec = { 68 9e [2] 5a bc [2] 5c 89 [2] 72 89 [2] 4d 95 }

  condition:
    any of them
}