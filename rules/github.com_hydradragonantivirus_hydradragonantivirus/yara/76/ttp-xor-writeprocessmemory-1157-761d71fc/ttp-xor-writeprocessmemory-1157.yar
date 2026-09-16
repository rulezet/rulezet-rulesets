rule TTP_XOR_WriteProcessMemory_1157 {
  strings:
    $key_1157 = { 46 25 [2] 74 07 [2] 72 32 [2] 5c 32 [2] 63 2e }

  condition:
    any of them
}