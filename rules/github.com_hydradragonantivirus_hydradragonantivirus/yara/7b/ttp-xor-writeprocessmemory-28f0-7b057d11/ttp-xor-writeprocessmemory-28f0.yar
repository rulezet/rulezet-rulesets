rule TTP_XOR_WriteProcessMemory_28f0 {
  strings:
    $key_28f0 = { 7f 82 [2] 4d a0 [2] 4b 95 [2] 65 95 [2] 5a 89 }

  condition:
    any of them
}