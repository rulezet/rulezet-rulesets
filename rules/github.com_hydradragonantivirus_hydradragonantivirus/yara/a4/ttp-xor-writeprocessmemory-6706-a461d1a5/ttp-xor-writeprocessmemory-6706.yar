rule TTP_XOR_WriteProcessMemory_6706 {
  strings:
    $key_6706 = { 30 74 [2] 02 56 [2] 04 63 [2] 2a 63 [2] 15 7f }

  condition:
    any of them
}