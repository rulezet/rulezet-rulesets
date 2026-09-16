rule TTP_XOR_WriteProcessMemory_4533 {
  strings:
    $key_4533 = { 12 41 [2] 20 63 [2] 26 56 [2] 08 56 [2] 37 4a }

  condition:
    any of them
}