rule TTP_XOR_WriteProcessMemory_64c8 {
  strings:
    $key_64c8 = { 33 ba [2] 01 98 [2] 07 ad [2] 29 ad [2] 16 b1 }

  condition:
    any of them
}