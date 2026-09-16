rule TTP_XOR_WriteProcessMemory_e2ce {
  strings:
    $key_e2ce = { b5 bc [2] 87 9e [2] 81 ab [2] af ab [2] 90 b7 }

  condition:
    any of them
}