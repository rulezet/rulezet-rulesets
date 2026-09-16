rule TTP_XOR_WriteProcessMemory_30ce {
  strings:
    $key_30ce = { 67 bc [2] 55 9e [2] 53 ab [2] 7d ab [2] 42 b7 }

  condition:
    any of them
}