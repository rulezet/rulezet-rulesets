rule TTP_XOR_WriteProcessMemory_6930 {
  strings:
    $key_6930 = { 3e 42 [2] 0c 60 [2] 0a 55 [2] 24 55 [2] 1b 49 }

  condition:
    any of them
}