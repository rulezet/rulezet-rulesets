rule TTP_XOR_WriteProcessMemory_60ed {
  strings:
    $key_60ed = { 37 9f [2] 05 bd [2] 03 88 [2] 2d 88 [2] 12 94 }

  condition:
    any of them
}