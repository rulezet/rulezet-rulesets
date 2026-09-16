rule TTP_XOR_WriteProcessMemory_21f7 {
  strings:
    $key_21f7 = { 76 85 [2] 44 a7 [2] 42 92 [2] 6c 92 [2] 53 8e }

  condition:
    any of them
}