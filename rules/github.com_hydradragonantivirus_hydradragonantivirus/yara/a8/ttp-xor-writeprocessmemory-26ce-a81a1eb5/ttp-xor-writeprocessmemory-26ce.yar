rule TTP_XOR_WriteProcessMemory_26ce {
  strings:
    $key_26ce = { 71 bc [2] 43 9e [2] 45 ab [2] 6b ab [2] 54 b7 }

  condition:
    any of them
}