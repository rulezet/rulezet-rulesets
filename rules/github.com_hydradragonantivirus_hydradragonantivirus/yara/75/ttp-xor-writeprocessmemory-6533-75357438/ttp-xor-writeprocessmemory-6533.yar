rule TTP_XOR_WriteProcessMemory_6533 {
  strings:
    $key_6533 = { 32 41 [2] 00 63 [2] 06 56 [2] 28 56 [2] 17 4a }

  condition:
    any of them
}