rule TTP_XOR_WriteProcessMemory_01ec {
  strings:
    $key_01ec = { 56 9e [2] 64 bc [2] 62 89 [2] 4c 89 [2] 73 95 }

  condition:
    any of them
}