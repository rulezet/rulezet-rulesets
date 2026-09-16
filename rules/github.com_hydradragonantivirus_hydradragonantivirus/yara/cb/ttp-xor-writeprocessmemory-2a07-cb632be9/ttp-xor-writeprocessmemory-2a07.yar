rule TTP_XOR_WriteProcessMemory_2a07 {
  strings:
    $key_2a07 = { 7d 75 [2] 4f 57 [2] 49 62 [2] 67 62 [2] 58 7e }

  condition:
    any of them
}