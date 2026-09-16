rule TTP_XOR_WriteProcessMemory_4563 {
  strings:
    $key_4563 = { 12 11 [2] 20 33 [2] 26 06 [2] 08 06 [2] 37 1a }

  condition:
    any of them
}