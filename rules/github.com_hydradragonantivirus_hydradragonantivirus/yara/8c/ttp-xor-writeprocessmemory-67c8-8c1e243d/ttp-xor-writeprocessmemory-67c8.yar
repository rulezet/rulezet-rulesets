rule TTP_XOR_WriteProcessMemory_67c8 {
  strings:
    $key_67c8 = { 30 ba [2] 02 98 [2] 04 ad [2] 2a ad [2] 15 b1 }

  condition:
    any of them
}