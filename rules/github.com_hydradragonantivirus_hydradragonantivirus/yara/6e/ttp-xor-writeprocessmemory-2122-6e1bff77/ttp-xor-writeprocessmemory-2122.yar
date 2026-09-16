rule TTP_XOR_WriteProcessMemory_2122 {
  strings:
    $key_2122 = { 76 50 [2] 44 72 [2] 42 47 [2] 6c 47 [2] 53 5b }

  condition:
    any of them
}