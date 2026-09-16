rule TTP_XOR_WriteProcessMemory_3112 {
  strings:
    $key_3112 = { 66 60 [2] 54 42 [2] 52 77 [2] 7c 77 [2] 43 6b }

  condition:
    any of them
}