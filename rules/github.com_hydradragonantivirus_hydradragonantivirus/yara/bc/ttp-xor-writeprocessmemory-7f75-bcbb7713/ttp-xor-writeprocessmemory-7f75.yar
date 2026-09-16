rule TTP_XOR_WriteProcessMemory_7f75 {
  strings:
    $key_7f75 = { 28 07 [2] 1a 25 [2] 1c 10 [2] 32 10 [2] 0d 0c }

  condition:
    any of them
}