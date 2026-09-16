rule TTP_XOR_WriteProcessMemory_6606 {
  strings:
    $key_6606 = { 31 74 [2] 03 56 [2] 05 63 [2] 2b 63 [2] 14 7f }

  condition:
    any of them
}