rule TTP_XOR_WriteProcessMemory_2ece {
  strings:
    $key_2ece = { 79 bc [2] 4b 9e [2] 4d ab [2] 63 ab [2] 5c b7 }

  condition:
    any of them
}