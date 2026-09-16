rule TTP_XOR_WriteProcessMemory_37c8 {
  strings:
    $key_37c8 = { 60 ba [2] 52 98 [2] 54 ad [2] 7a ad [2] 45 b1 }

  condition:
    any of them
}