rule TTP_XOR_WriteProcessMemory_6ece {
  strings:
    $key_6ece = { 39 bc [2] 0b 9e [2] 0d ab [2] 23 ab [2] 1c b7 }

  condition:
    any of them
}