rule TTP_XOR_WriteProcessMemory_7247 {
  strings:
    $key_7247 = { 25 35 [2] 17 17 [2] 11 22 [2] 3f 22 [2] 00 3e }

  condition:
    any of them
}