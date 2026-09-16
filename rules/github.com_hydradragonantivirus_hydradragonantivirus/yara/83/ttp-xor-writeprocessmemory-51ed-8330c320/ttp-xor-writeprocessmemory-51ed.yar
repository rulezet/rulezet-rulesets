rule TTP_XOR_WriteProcessMemory_51ed {
  strings:
    $key_51ed = { 06 9f [2] 34 bd [2] 32 88 [2] 1c 88 [2] 23 94 }

  condition:
    any of them
}