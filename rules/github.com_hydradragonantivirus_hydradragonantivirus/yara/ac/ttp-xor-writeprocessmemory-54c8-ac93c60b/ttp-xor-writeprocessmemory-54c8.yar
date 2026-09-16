rule TTP_XOR_WriteProcessMemory_54c8 {
  strings:
    $key_54c8 = { 03 ba [2] 31 98 [2] 37 ad [2] 19 ad [2] 26 b1 }

  condition:
    any of them
}