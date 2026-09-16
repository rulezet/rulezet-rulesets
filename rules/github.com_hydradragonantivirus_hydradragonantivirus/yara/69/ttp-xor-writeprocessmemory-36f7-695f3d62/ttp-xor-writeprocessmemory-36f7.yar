rule TTP_XOR_WriteProcessMemory_36f7 {
  strings:
    $key_36f7 = { 61 85 [2] 53 a7 [2] 55 92 [2] 7b 92 [2] 44 8e }

  condition:
    any of them
}