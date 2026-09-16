rule TTP_XOR_WriteProcessMemory_10ed {
  strings:
    $key_10ed = { 47 9f [2] 75 bd [2] 73 88 [2] 5d 88 [2] 62 94 }

  condition:
    any of them
}