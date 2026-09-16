rule TTP_XOR_WriteProcessMemory_a99b {
  strings:
    $key_a99b = { fe e9 [2] cc cb [2] ca fe [2] e4 fe [2] db e2 }

  condition:
    any of them
}