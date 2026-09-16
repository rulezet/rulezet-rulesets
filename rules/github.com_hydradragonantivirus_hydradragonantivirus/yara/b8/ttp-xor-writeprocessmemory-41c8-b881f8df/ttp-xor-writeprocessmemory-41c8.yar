rule TTP_XOR_WriteProcessMemory_41c8 {
  strings:
    $key_41c8 = { 16 ba [2] 24 98 [2] 22 ad [2] 0c ad [2] 33 b1 }

  condition:
    any of them
}