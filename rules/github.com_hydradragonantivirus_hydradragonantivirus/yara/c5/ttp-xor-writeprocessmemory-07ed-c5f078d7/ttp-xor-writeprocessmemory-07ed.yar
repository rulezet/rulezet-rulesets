rule TTP_XOR_WriteProcessMemory_07ed {
  strings:
    $key_07ed = { 50 9f [2] 62 bd [2] 64 88 [2] 4a 88 [2] 75 94 }

  condition:
    any of them
}