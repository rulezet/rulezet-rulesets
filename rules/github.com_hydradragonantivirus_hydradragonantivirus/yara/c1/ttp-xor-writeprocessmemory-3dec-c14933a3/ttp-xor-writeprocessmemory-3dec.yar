rule TTP_XOR_WriteProcessMemory_3dec {
  strings:
    $key_3dec = { 6a 9e [2] 58 bc [2] 5e 89 [2] 70 89 [2] 4f 95 }

  condition:
    any of them
}