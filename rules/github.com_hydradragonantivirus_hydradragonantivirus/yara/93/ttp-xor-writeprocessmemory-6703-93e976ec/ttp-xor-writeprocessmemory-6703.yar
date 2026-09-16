rule TTP_XOR_WriteProcessMemory_6703 {
  strings:
    $key_6703 = { 30 71 [2] 02 53 [2] 04 66 [2] 2a 66 [2] 15 7a }

  condition:
    any of them
}