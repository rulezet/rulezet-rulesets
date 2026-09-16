rule TTP_XOR_WriteProcessMemory_3060 {
  strings:
    $key_3060 = { 67 12 [2] 55 30 [2] 53 05 [2] 7d 05 [2] 42 19 }

  condition:
    any of them
}