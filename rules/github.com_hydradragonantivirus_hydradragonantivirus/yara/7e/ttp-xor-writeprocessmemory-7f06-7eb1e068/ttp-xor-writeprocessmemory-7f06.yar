rule TTP_XOR_WriteProcessMemory_7f06 {
  strings:
    $key_7f06 = { 28 74 [2] 1a 56 [2] 1c 63 [2] 32 63 [2] 0d 7f }

  condition:
    any of them
}