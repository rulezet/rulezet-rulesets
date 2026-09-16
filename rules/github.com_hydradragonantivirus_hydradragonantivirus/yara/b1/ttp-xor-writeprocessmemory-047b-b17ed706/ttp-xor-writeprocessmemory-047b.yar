rule TTP_XOR_WriteProcessMemory_047b {
  strings:
    $key_047b = { 53 09 [2] 61 2b [2] 67 1e [2] 49 1e [2] 76 02 }

  condition:
    any of them
}