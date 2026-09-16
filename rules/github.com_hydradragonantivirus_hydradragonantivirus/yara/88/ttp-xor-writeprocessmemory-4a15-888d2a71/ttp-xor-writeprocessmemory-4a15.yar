rule TTP_XOR_WriteProcessMemory_4a15 {
  strings:
    $key_4a15 = { 1d 67 [2] 2f 45 [2] 29 70 [2] 07 70 [2] 38 6c }

  condition:
    any of them
}