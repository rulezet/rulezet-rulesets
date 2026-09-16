rule TTP_XOR_WriteProcessMemory_53ce {
  strings:
    $key_53ce = { 04 bc [2] 36 9e [2] 30 ab [2] 1e ab [2] 21 b7 }

  condition:
    any of them
}