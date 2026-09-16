rule TTP_XOR_WriteProcessMemory_46ed {
  strings:
    $key_46ed = { 11 9f [2] 23 bd [2] 25 88 [2] 0b 88 [2] 34 94 }

  condition:
    any of them
}