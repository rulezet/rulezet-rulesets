rule TTP_XOR_WriteProcessMemory_21ce {
  strings:
    $key_21ce = { 76 bc [2] 44 9e [2] 42 ab [2] 6c ab [2] 53 b7 }

  condition:
    any of them
}