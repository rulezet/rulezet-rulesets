rule TTP_XOR_WriteProcessMemory_7133 {
  strings:
    $key_7133 = { 26 41 [2] 14 63 [2] 12 56 [2] 3c 56 [2] 03 4a }

  condition:
    any of them
}