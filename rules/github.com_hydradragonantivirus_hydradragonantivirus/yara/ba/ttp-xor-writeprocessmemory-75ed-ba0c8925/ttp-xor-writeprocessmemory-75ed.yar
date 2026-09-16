rule TTP_XOR_WriteProcessMemory_75ed {
  strings:
    $key_75ed = { 22 9f [2] 10 bd [2] 16 88 [2] 38 88 [2] 07 94 }

  condition:
    any of them
}