rule TTP_XOR_WriteProcessMemory_63e3 {
  strings:
    $key_63e3 = { 34 91 [2] 06 b3 [2] 00 86 [2] 2e 86 [2] 11 9a }

  condition:
    any of them
}