rule TTP_XOR_WriteProcessMemory_24ec {
  strings:
    $key_24ec = { 73 9e [2] 41 bc [2] 47 89 [2] 69 89 [2] 56 95 }

  condition:
    any of them
}