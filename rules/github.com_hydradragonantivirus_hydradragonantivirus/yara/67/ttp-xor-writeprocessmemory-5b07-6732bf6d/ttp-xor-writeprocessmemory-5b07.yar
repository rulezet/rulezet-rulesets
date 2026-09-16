rule TTP_XOR_WriteProcessMemory_5b07 {
  strings:
    $key_5b07 = { 0c 75 [2] 3e 57 [2] 38 62 [2] 16 62 [2] 29 7e }

  condition:
    any of them
}