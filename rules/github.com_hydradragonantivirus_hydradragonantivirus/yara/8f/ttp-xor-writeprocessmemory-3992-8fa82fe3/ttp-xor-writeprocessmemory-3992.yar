rule TTP_XOR_WriteProcessMemory_3992 {
  strings:
    $key_3992 = { 6e e0 [2] 5c c2 [2] 5a f7 [2] 74 f7 [2] 4b eb }

  condition:
    any of them
}