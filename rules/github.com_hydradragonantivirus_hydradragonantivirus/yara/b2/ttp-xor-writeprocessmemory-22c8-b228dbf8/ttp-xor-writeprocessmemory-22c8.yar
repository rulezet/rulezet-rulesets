rule TTP_XOR_WriteProcessMemory_22c8 {
  strings:
    $key_22c8 = { 75 ba [2] 47 98 [2] 41 ad [2] 6f ad [2] 50 b1 }

  condition:
    any of them
}