rule TTP_XOR_WriteProcessMemory_2222 {
  strings:
    $key_2222 = { 75 50 [2] 47 72 [2] 41 47 [2] 6f 47 [2] 50 5b }

  condition:
    any of them
}