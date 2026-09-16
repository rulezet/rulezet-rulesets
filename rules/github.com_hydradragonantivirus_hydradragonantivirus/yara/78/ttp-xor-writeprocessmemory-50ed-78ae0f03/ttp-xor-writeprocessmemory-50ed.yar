rule TTP_XOR_WriteProcessMemory_50ed {
  strings:
    $key_50ed = { 07 9f [2] 35 bd [2] 33 88 [2] 1d 88 [2] 22 94 }

  condition:
    any of them
}