rule TTP_XOR_WriteProcessMemory_28a3 {
  strings:
    $key_28a3 = { 7f d1 [2] 4d f3 [2] 4b c6 [2] 65 c6 [2] 5a da }

  condition:
    any of them
}