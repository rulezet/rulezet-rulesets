rule TTP_XOR_WriteProcessMemory_50ce {
  strings:
    $key_50ce = { 07 bc [2] 35 9e [2] 33 ab [2] 1d ab [2] 22 b7 }

  condition:
    any of them
}