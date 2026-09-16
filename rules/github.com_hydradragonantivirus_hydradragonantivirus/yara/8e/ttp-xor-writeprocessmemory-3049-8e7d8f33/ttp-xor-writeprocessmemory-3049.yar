rule TTP_XOR_WriteProcessMemory_3049 {
  strings:
    $key_3049 = { 67 3b [2] 55 19 [2] 53 2c [2] 7d 2c [2] 42 30 }

  condition:
    any of them
}