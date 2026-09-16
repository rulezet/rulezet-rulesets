rule TTP_XOR_WriteProcessMemory_7137 {
  strings:
    $key_7137 = { 26 45 [2] 14 67 [2] 12 52 [2] 3c 52 [2] 03 4e }

  condition:
    any of them
}