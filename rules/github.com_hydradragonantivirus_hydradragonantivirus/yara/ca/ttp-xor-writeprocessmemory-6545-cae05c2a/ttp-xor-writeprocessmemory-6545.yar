rule TTP_XOR_WriteProcessMemory_6545 {
  strings:
    $key_6545 = { 32 37 [2] 00 15 [2] 06 20 [2] 28 20 [2] 17 3c }

  condition:
    any of them
}