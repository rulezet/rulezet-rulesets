rule TTP_XOR_WriteProcessMemory_b7ce {
  strings:
    $key_b7ce = { e0 bc [2] d2 9e [2] d4 ab [2] fa ab [2] c5 b7 }

  condition:
    any of them
}