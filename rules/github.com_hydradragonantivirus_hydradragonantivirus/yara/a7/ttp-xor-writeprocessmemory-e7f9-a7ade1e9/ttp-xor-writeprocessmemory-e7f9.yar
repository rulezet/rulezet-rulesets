rule TTP_XOR_WriteProcessMemory_e7f9 {
  strings:
    $key_e7f9 = { b0 8b [2] 82 a9 [2] 84 9c [2] aa 9c [2] 95 80 }

  condition:
    any of them
}