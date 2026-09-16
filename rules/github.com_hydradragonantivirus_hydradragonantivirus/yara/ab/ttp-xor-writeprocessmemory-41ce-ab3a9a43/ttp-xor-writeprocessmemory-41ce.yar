rule TTP_XOR_WriteProcessMemory_41ce {
  strings:
    $key_41ce = { 16 bc [2] 24 9e [2] 22 ab [2] 0c ab [2] 33 b7 }

  condition:
    any of them
}