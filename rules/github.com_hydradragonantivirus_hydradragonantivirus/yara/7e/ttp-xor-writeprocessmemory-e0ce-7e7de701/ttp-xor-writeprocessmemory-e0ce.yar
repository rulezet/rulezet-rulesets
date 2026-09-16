rule TTP_XOR_WriteProcessMemory_e0ce {
  strings:
    $key_e0ce = { b7 bc [2] 85 9e [2] 83 ab [2] ad ab [2] 92 b7 }

  condition:
    any of them
}