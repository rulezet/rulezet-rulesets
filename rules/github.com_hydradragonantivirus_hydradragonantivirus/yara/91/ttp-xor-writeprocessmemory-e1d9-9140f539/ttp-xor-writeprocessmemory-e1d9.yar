rule TTP_XOR_WriteProcessMemory_e1d9 {
  strings:
    $key_e1d9 = { b6 ab [2] 84 89 [2] 82 bc [2] ac bc [2] 93 a0 }

  condition:
    any of them
}