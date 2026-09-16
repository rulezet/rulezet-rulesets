rule TTP_XOR_WriteProcessMemory_40ed {
  strings:
    $key_40ed = { 17 9f [2] 25 bd [2] 23 88 [2] 0d 88 [2] 32 94 }

  condition:
    any of them
}