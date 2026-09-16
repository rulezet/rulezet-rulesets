rule TTP_XOR_WriteProcessMemory_2736 {
  strings:
    $key_2736 = { 70 44 [2] 42 66 [2] 44 53 [2] 6a 53 [2] 55 4f }

  condition:
    any of them
}