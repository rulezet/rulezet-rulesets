rule TTP_XOR_WriteProcessMemory_5543 {
  strings:
    $key_5543 = { 02 31 [2] 30 13 [2] 36 26 [2] 18 26 [2] 27 3a }

  condition:
    any of them
}