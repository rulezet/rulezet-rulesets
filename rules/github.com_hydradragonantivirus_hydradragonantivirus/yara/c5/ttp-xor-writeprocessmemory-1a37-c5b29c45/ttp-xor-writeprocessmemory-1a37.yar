rule TTP_XOR_WriteProcessMemory_1a37 {
  strings:
    $key_1a37 = { 4d 45 [2] 7f 67 [2] 79 52 [2] 57 52 [2] 68 4e }

  condition:
    any of them
}