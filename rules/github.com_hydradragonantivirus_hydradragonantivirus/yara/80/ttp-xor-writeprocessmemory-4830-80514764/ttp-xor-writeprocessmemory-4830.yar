rule TTP_XOR_WriteProcessMemory_4830 {
  strings:
    $key_4830 = { 1f 42 [2] 2d 60 [2] 2b 55 [2] 05 55 [2] 3a 49 }

  condition:
    any of them
}