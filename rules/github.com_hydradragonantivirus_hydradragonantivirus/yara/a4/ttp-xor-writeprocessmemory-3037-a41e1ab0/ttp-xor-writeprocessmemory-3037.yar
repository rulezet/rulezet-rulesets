rule TTP_XOR_WriteProcessMemory_3037 {
  strings:
    $key_3037 = { 67 45 [2] 55 67 [2] 53 52 [2] 7d 52 [2] 42 4e }

  condition:
    any of them
}