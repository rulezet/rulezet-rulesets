rule TTP_XOR_WriteProcessMemory_07e3 {
  strings:
    $key_07e3 = { 50 91 [2] 62 b3 [2] 64 86 [2] 4a 86 [2] 75 9a }

  condition:
    any of them
}