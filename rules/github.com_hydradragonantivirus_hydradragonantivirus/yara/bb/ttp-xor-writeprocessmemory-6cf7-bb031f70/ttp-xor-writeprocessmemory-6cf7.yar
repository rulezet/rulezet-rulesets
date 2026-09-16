rule TTP_XOR_WriteProcessMemory_6cf7 {
  strings:
    $key_6cf7 = { 3b 85 [2] 09 a7 [2] 0f 92 [2] 21 92 [2] 1e 8e }

  condition:
    any of them
}