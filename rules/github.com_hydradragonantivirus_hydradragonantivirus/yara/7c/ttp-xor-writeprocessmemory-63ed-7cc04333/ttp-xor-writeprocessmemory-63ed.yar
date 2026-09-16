rule TTP_XOR_WriteProcessMemory_63ed {
  strings:
    $key_63ed = { 34 9f [2] 06 bd [2] 00 88 [2] 2e 88 [2] 11 94 }

  condition:
    any of them
}