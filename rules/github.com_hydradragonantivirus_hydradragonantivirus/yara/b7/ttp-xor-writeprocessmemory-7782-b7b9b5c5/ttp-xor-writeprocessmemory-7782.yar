rule TTP_XOR_WriteProcessMemory_7782 {
  strings:
    $key_7782 = { 20 f0 [2] 12 d2 [2] 14 e7 [2] 3a e7 [2] 05 fb }

  condition:
    any of them
}