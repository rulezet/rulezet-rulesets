rule TTP_XOR_WriteProcessMemory_36f0 {
  strings:
    $key_36f0 = { 61 82 [2] 53 a0 [2] 55 95 [2] 7b 95 [2] 44 89 }

  condition:
    any of them
}