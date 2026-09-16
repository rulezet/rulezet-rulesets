rule TTP_XOR_WriteProcessMemory_6f06 {
  strings:
    $key_6f06 = { 38 74 [2] 0a 56 [2] 0c 63 [2] 22 63 [2] 1d 7f }

  condition:
    any of them
}