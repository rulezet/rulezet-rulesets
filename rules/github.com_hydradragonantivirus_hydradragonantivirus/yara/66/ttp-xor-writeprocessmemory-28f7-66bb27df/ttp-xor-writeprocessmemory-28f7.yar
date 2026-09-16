rule TTP_XOR_WriteProcessMemory_28f7 {
  strings:
    $key_28f7 = { 7f 85 [2] 4d a7 [2] 4b 92 [2] 65 92 [2] 5a 8e }

  condition:
    any of them
}