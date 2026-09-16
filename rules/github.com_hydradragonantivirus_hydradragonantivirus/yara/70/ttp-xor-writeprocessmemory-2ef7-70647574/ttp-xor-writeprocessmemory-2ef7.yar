rule TTP_XOR_WriteProcessMemory_2ef7 {
  strings:
    $key_2ef7 = { 79 85 [2] 4b a7 [2] 4d 92 [2] 63 92 [2] 5c 8e }

  condition:
    any of them
}