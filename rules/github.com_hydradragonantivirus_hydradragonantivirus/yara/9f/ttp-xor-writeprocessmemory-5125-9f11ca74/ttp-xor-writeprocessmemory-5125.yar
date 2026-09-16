rule TTP_XOR_WriteProcessMemory_5125 {
  strings:
    $key_5125 = { 06 57 [2] 34 75 [2] 32 40 [2] 1c 40 [2] 23 5c }

  condition:
    any of them
}