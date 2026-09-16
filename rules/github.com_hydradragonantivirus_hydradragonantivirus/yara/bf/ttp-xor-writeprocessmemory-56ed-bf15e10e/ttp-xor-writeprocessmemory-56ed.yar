rule TTP_XOR_WriteProcessMemory_56ed {
  strings:
    $key_56ed = { 01 9f [2] 33 bd [2] 35 88 [2] 1b 88 [2] 24 94 }

  condition:
    any of them
}