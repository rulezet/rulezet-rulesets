rule TTP_XOR_WriteProcessMemory_2ab0 {
  strings:
    $key_2ab0 = { 7d c2 [2] 4f e0 [2] 49 d5 [2] 67 d5 [2] 58 c9 }

  condition:
    any of them
}