rule TTP_XOR_WriteProcessMemory_5137 {
  strings:
    $key_5137 = { 06 45 [2] 34 67 [2] 32 52 [2] 1c 52 [2] 23 4e }

  condition:
    any of them
}