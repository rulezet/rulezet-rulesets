rule TTP_XOR_WriteProcessMemory_5ece {
  strings:
    $key_5ece = { 09 bc [2] 3b 9e [2] 3d ab [2] 13 ab [2] 2c b7 }

  condition:
    any of them
}