rule TTP_XOR_WriteProcessMemory_51c8 {
  strings:
    $key_51c8 = { 06 ba [2] 34 98 [2] 32 ad [2] 1c ad [2] 23 b1 }

  condition:
    any of them
}