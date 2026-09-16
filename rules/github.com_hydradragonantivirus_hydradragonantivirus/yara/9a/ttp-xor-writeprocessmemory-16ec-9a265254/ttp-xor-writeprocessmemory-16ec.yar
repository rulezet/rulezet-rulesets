rule TTP_XOR_WriteProcessMemory_16ec {
  strings:
    $key_16ec = { 41 9e [2] 73 bc [2] 75 89 [2] 5b 89 [2] 64 95 }

  condition:
    any of them
}