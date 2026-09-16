rule TTP_XOR_WriteProcessMemory_45c8 {
  strings:
    $key_45c8 = { 12 ba [2] 20 98 [2] 26 ad [2] 08 ad [2] 37 b1 }

  condition:
    any of them
}