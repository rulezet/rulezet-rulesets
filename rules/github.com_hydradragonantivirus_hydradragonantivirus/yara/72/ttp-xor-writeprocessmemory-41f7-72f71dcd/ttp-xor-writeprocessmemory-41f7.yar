rule TTP_XOR_WriteProcessMemory_41f7 {
  strings:
    $key_41f7 = { 16 85 [2] 24 a7 [2] 22 92 [2] 0c 92 [2] 33 8e }

  condition:
    any of them
}