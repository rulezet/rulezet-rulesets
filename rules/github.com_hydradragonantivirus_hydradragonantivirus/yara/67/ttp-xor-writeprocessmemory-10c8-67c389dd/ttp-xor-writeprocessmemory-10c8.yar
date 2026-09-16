rule TTP_XOR_WriteProcessMemory_10c8 {
  strings:
    $key_10c8 = { 47 ba [2] 75 98 [2] 73 ad [2] 5d ad [2] 62 b1 }

  condition:
    any of them
}