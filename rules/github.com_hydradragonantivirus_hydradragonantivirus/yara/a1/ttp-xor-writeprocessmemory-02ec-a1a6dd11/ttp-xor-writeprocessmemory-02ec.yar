rule TTP_XOR_WriteProcessMemory_02ec {
  strings:
    $key_02ec = { 55 9e [2] 67 bc [2] 61 89 [2] 4f 89 [2] 70 95 }

  condition:
    any of them
}