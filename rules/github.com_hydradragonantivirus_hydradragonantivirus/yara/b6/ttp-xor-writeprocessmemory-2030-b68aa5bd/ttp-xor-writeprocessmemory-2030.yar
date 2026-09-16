rule TTP_XOR_WriteProcessMemory_2030 {
  strings:
    $key_2030 = { 77 42 [2] 45 60 [2] 43 55 [2] 6d 55 [2] 52 49 }

  condition:
    any of them
}