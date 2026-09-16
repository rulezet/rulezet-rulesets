rule TTP_XOR_WriteProcessMemory_03f6 {
  strings:
    $key_03f6 = { 54 84 [2] 66 a6 [2] 60 93 [2] 4e 93 [2] 71 8f }

  condition:
    any of them
}