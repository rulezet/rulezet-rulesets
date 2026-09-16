rule TTP_XOR_WriteProcessMemory_e43b {
  strings:
    $key_e43b = { b3 49 [2] 81 6b [2] 87 5e [2] a9 5e [2] 96 42 }

  condition:
    any of them
}