rule TTP_XOR_WriteProcessMemory_5402 {
  strings:
    $key_5402 = { 03 70 [2] 31 52 [2] 37 67 [2] 19 67 [2] 26 7b }

  condition:
    any of them
}