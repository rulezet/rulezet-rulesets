rule TTP_XOR_WriteProcessMemory_3606 {
  strings:
    $key_3606 = { 61 74 [2] 53 56 [2] 55 63 [2] 7b 63 [2] 44 7f }

  condition:
    any of them
}