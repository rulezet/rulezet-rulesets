rule TTP_XOR_WriteProcessMemory_21ec {
  strings:
    $key_21ec = { 76 9e [2] 44 bc [2] 42 89 [2] 6c 89 [2] 53 95 }

  condition:
    any of them
}