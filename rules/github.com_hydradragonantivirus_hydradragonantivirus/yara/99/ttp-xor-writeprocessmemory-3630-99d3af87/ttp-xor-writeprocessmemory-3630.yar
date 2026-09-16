rule TTP_XOR_WriteProcessMemory_3630 {
  strings:
    $key_3630 = { 61 42 [2] 53 60 [2] 55 55 [2] 7b 55 [2] 44 49 }

  condition:
    any of them
}