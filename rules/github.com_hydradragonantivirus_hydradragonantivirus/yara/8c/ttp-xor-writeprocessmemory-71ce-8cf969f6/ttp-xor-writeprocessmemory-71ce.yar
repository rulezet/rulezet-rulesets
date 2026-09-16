rule TTP_XOR_WriteProcessMemory_71ce {
  strings:
    $key_71ce = { 26 bc [2] 14 9e [2] 12 ab [2] 3c ab [2] 03 b7 }

  condition:
    any of them
}