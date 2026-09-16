rule TTP_XOR_WriteProcessMemory_773b {
  strings:
    $key_773b = { 20 49 [2] 12 6b [2] 14 5e [2] 3a 5e [2] 05 42 }

  condition:
    any of them
}