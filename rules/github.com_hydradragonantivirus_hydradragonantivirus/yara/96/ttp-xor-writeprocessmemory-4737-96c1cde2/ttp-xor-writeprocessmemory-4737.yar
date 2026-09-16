rule TTP_XOR_WriteProcessMemory_4737 {
  strings:
    $key_4737 = { 10 45 [2] 22 67 [2] 24 52 [2] 0a 52 [2] 35 4e }

  condition:
    any of them
}