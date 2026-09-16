rule TTP_XOR_WriteProcessMemory_6d07 {
  strings:
    $key_6d07 = { 3a 75 [2] 08 57 [2] 0e 62 [2] 20 62 [2] 1f 7e }

  condition:
    any of them
}