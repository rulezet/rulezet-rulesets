rule TTP_XOR_WriteProcessMemory_525b {
  strings:
    $key_525b = { 05 29 [2] 37 0b [2] 31 3e [2] 1f 3e [2] 20 22 }

  condition:
    any of them
}