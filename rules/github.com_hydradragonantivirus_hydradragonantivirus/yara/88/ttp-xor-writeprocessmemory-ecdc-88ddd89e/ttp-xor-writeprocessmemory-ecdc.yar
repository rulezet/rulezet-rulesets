rule TTP_XOR_WriteProcessMemory_ecdc {
  strings:
    $key_ecdc = { bb ae [2] 89 8c [2] 8f b9 [2] a1 b9 [2] 9e a5 }

  condition:
    any of them
}