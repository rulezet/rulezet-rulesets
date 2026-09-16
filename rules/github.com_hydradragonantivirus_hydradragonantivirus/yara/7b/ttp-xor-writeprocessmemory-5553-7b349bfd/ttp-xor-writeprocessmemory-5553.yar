rule TTP_XOR_WriteProcessMemory_5553 {
  strings:
    $key_5553 = { 02 21 [2] 30 03 [2] 36 36 [2] 18 36 [2] 27 2a }

  condition:
    any of them
}