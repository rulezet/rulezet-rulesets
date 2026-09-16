rule TTP_XOR_WriteProcessMemory_526b {
  strings:
    $key_526b = { 05 19 [2] 37 3b [2] 31 0e [2] 1f 0e [2] 20 12 }

  condition:
    any of them
}