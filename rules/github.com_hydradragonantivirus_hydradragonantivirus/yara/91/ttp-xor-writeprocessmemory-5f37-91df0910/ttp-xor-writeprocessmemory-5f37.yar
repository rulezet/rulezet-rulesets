rule TTP_XOR_WriteProcessMemory_5f37 {
  strings:
    $key_5f37 = { 08 45 [2] 3a 67 [2] 3c 52 [2] 12 52 [2] 2d 4e }

  condition:
    any of them
}