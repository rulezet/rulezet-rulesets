rule TTP_XOR_WriteProcessMemory_1830 {
  strings:
    $key_1830 = { 4f 42 [2] 7d 60 [2] 7b 55 [2] 55 55 [2] 6a 49 }

  condition:
    any of them
}