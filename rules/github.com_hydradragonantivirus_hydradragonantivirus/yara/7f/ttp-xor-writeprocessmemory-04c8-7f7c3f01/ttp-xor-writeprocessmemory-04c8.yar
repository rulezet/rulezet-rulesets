rule TTP_XOR_WriteProcessMemory_04c8 {
  strings:
    $key_04c8 = { 53 ba [2] 61 98 [2] 67 ad [2] 49 ad [2] 76 b1 }

  condition:
    any of them
}