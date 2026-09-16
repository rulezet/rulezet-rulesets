rule TTP_XOR_WriteProcessMemory_3061 {
  strings:
    $key_3061 = { 67 13 [2] 55 31 [2] 53 04 [2] 7d 04 [2] 42 18 }

  condition:
    any of them
}