rule TTP_XOR_WriteProcessMemory_66f7 {
  strings:
    $key_66f7 = { 31 85 [2] 03 a7 [2] 05 92 [2] 2b 92 [2] 14 8e }

  condition:
    any of them
}