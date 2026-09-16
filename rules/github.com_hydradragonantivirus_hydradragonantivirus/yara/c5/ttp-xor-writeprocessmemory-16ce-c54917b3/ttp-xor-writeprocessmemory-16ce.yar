rule TTP_XOR_WriteProcessMemory_16ce {
  strings:
    $key_16ce = { 41 bc [2] 73 9e [2] 75 ab [2] 5b ab [2] 64 b7 }

  condition:
    any of them
}