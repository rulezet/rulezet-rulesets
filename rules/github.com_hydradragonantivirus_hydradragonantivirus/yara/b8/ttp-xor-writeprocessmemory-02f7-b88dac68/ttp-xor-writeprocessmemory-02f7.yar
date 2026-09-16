rule TTP_XOR_WriteProcessMemory_02f7 {
  strings:
    $key_02f7 = { 55 85 [2] 67 a7 [2] 61 92 [2] 4f 92 [2] 70 8e }

  condition:
    any of them
}