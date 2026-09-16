rule TTP_XOR_WriteProcessMemory_1f07 {
  strings:
    $key_1f07 = { 48 75 [2] 7a 57 [2] 7c 62 [2] 52 62 [2] 6d 7e }

  condition:
    any of them
}