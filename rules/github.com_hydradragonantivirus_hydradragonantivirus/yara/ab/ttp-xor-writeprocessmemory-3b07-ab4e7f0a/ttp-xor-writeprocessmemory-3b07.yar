rule TTP_XOR_WriteProcessMemory_3b07 {
  strings:
    $key_3b07 = { 6c 75 [2] 5e 57 [2] 58 62 [2] 76 62 [2] 49 7e }

  condition:
    any of them
}