rule TTP_XOR_WriteProcessMemory_65c8 {
  strings:
    $key_65c8 = { 32 ba [2] 00 98 [2] 06 ad [2] 28 ad [2] 17 b1 }

  condition:
    any of them
}