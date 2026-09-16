rule TTP_XOR_WriteProcessMemory_66ed {
  strings:
    $key_66ed = { 31 9f [2] 03 bd [2] 05 88 [2] 2b 88 [2] 14 94 }

  condition:
    any of them
}