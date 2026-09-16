rule TTP_XOR_WriteProcessMemory_1dec {
  strings:
    $key_1dec = { 4a 9e [2] 78 bc [2] 7e 89 [2] 50 89 [2] 6f 95 }

  condition:
    any of them
}