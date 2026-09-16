rule TTP_XOR_WriteProcessMemory_4347 {
  strings:
    $key_4347 = { 14 35 [2] 26 17 [2] 20 22 [2] 0e 22 [2] 31 3e }

  condition:
    any of them
}