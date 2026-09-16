rule TTP_XOR_WriteProcessMemory_47e3 {
  strings:
    $key_47e3 = { 10 91 [2] 22 b3 [2] 24 86 [2] 0a 86 [2] 35 9a }

  condition:
    any of them
}