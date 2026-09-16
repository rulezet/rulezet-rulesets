rule TTP_XOR_WriteProcessMemory_06ec {
  strings:
    $key_06ec = { 51 9e [2] 63 bc [2] 65 89 [2] 4b 89 [2] 74 95 }

  condition:
    any of them
}