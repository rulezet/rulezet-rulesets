rule TTP_XOR_WriteProcessMemory_7537 {
  strings:
    $key_7537 = { 22 45 [2] 10 67 [2] 16 52 [2] 38 52 [2] 07 4e }

  condition:
    any of them
}