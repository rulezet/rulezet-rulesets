rule TTP_XOR_WriteProcessMemory_1f25 {
  strings:
    $key_1f25 = { 48 57 [2] 7a 75 [2] 7c 40 [2] 52 40 [2] 6d 5c }

  condition:
    any of them
}