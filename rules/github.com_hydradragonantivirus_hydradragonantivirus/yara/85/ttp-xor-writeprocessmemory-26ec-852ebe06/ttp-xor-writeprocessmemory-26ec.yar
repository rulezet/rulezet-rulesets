rule TTP_XOR_WriteProcessMemory_26ec {
  strings:
    $key_26ec = { 71 9e [2] 43 bc [2] 45 89 [2] 6b 89 [2] 54 95 }

  condition:
    any of them
}