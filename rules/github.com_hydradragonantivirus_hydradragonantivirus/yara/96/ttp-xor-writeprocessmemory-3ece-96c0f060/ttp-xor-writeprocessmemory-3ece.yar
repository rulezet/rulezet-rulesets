rule TTP_XOR_WriteProcessMemory_3ece {
  strings:
    $key_3ece = { 69 bc [2] 5b 9e [2] 5d ab [2] 73 ab [2] 4c b7 }

  condition:
    any of them
}