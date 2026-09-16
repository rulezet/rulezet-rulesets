rule TTP_XOR_WriteProcessMemory_6e62 {
  strings:
    $key_6e62 = { 39 10 [2] 0b 32 [2] 0d 07 [2] 23 07 [2] 1c 1b }

  condition:
    any of them
}