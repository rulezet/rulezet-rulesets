rule TTP_XOR_WriteProcessMemory_2ad9 {
  strings:
    $key_2ad9 = { 7d ab [2] 4f 89 [2] 49 bc [2] 67 bc [2] 58 a0 }

  condition:
    any of them
}