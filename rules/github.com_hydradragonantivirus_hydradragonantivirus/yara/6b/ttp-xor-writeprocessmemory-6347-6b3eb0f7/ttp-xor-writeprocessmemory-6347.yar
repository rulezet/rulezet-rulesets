rule TTP_XOR_WriteProcessMemory_6347 {
  strings:
    $key_6347 = { 34 35 [2] 06 17 [2] 00 22 [2] 2e 22 [2] 11 3e }

  condition:
    any of them
}