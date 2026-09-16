rule TTP_XOR_WriteProcessMemory_19f7 {
  strings:
    $key_19f7 = { 4e 85 [2] 7c a7 [2] 7a 92 [2] 54 92 [2] 6b 8e }

  condition:
    any of them
}