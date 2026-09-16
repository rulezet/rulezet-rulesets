rule TTP_XOR_WriteProcessMemory_71ed {
  strings:
    $key_71ed = { 26 9f [2] 14 bd [2] 12 88 [2] 3c 88 [2] 03 94 }

  condition:
    any of them
}