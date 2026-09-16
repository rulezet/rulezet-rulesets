rule TTP_XOR_WriteProcessMemory_3047 {
  strings:
    $key_3047 = { 67 35 [2] 55 17 [2] 53 22 [2] 7d 22 [2] 42 3e }

  condition:
    any of them
}