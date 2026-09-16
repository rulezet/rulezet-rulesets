rule TTP_XOR_WriteProcessMemory_05f7 {
  strings:
    $key_05f7 = { 52 85 [2] 60 a7 [2] 66 92 [2] 48 92 [2] 77 8e }

  condition:
    any of them
}