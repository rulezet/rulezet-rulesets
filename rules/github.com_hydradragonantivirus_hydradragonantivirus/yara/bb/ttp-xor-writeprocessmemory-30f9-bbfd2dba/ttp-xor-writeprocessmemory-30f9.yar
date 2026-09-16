rule TTP_XOR_WriteProcessMemory_30f9 {
  strings:
    $key_30f9 = { 67 8b [2] 55 a9 [2] 53 9c [2] 7d 9c [2] 42 80 }

  condition:
    any of them
}