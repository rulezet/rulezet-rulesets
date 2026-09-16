rule TTP_XOR_WriteProcessMemory_6721 {
  strings:
    $key_6721 = { 30 53 [2] 02 71 [2] 04 44 [2] 2a 44 [2] 15 58 }

  condition:
    any of them
}