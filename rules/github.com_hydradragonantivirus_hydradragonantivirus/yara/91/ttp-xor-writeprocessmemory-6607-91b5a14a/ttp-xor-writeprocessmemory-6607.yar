rule TTP_XOR_WriteProcessMemory_6607 {
  strings:
    $key_6607 = { 31 75 [2] 03 57 [2] 05 62 [2] 2b 62 [2] 14 7e }

  condition:
    any of them
}