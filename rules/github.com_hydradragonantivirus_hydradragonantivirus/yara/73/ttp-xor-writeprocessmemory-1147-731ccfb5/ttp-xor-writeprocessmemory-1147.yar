rule TTP_XOR_WriteProcessMemory_1147 {
  strings:
    $key_1147 = { 46 35 [2] 74 17 [2] 72 22 [2] 5c 22 [2] 63 3e }

  condition:
    any of them
}