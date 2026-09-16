rule TTP_XOR_WriteProcessMemory_5157 {
  strings:
    $key_5157 = { 06 25 [2] 34 07 [2] 32 32 [2] 1c 32 [2] 23 2e }

  condition:
    any of them
}