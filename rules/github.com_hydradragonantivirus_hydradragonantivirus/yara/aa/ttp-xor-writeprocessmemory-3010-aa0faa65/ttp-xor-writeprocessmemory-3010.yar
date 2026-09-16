rule TTP_XOR_WriteProcessMemory_3010 {
  strings:
    $key_3010 = { 67 62 [2] 55 40 [2] 53 75 [2] 7d 75 [2] 42 69 }

  condition:
    any of them
}