rule TTP_XOR_WriteProcessMemory_65e3 {
  strings:
    $key_65e3 = { 32 91 [2] 00 b3 [2] 06 86 [2] 28 86 [2] 17 9a }

  condition:
    any of them
}