rule TTP_XOR_WriteProcessMemory_0779 {
  strings:
    $key_0779 = { 50 0b [2] 62 29 [2] 64 1c [2] 4a 1c [2] 75 00 }

  condition:
    any of them
}