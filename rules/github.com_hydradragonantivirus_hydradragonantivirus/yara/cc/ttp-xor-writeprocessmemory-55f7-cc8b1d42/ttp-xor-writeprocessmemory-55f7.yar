rule TTP_XOR_WriteProcessMemory_55f7 {
  strings:
    $key_55f7 = { 02 85 [2] 30 a7 [2] 36 92 [2] 18 92 [2] 27 8e }

  condition:
    any of them
}