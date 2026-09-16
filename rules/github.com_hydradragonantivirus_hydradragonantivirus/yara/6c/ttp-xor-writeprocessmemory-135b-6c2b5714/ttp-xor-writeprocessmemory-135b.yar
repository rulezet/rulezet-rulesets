rule TTP_XOR_WriteProcessMemory_135b {
  strings:
    $key_135b = { 44 29 [2] 76 0b [2] 70 3e [2] 5e 3e [2] 61 22 }

  condition:
    any of them
}