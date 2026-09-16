rule TTP_XOR_WriteProcessMemory_4506 {
  strings:
    $key_4506 = { 12 74 [2] 20 56 [2] 26 63 [2] 08 63 [2] 37 7f }

  condition:
    any of them
}