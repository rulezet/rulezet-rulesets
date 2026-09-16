rule TTP_XOR_WriteProcessMemory_3bf1 {
  strings:
    $key_3bf1 = { 6c 83 [2] 5e a1 [2] 58 94 [2] 76 94 [2] 49 88 }

  condition:
    any of them
}