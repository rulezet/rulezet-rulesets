rule TTP_XOR_WriteProcessMemory_1547 {
  strings:
    $key_1547 = { 42 35 [2] 70 17 [2] 76 22 [2] 58 22 [2] 67 3e }

  condition:
    any of them
}