rule TTP_XOR_WriteProcessMemory_3020 {
  strings:
    $key_3020 = { 67 52 [2] 55 70 [2] 53 45 [2] 7d 45 [2] 42 59 }

  condition:
    any of them
}