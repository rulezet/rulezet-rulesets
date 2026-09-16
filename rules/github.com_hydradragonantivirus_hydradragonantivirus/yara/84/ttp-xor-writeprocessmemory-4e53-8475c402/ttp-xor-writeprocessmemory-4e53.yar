rule TTP_XOR_WriteProcessMemory_4e53 {
  strings:
    $key_4e53 = { 19 21 [2] 2b 03 [2] 2d 36 [2] 03 36 [2] 3c 2a }

  condition:
    any of them
}