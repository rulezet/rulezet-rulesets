rule TTP_XOR_WriteProcessMemory_4730 {
  strings:
    $key_4730 = { 10 42 [2] 22 60 [2] 24 55 [2] 0a 55 [2] 35 49 }

  condition:
    any of them
}