rule TTP_XOR_WriteProcessMemory_20ce {
  strings:
    $key_20ce = { 77 bc [2] 45 9e [2] 43 ab [2] 6d ab [2] 52 b7 }

  condition:
    any of them
}