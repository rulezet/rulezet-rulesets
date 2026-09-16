rule TTP_XOR_WriteProcessMemory_00ec {
  strings:
    $key_00ec = { 57 9e [2] 65 bc [2] 63 89 [2] 4d 89 [2] 72 95 }

  condition:
    any of them
}