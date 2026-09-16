rule TTP_XOR_WriteProcessMemory_6e53 {
  strings:
    $key_6e53 = { 39 21 [2] 0b 03 [2] 0d 36 [2] 23 36 [2] 1c 2a }

  condition:
    any of them
}