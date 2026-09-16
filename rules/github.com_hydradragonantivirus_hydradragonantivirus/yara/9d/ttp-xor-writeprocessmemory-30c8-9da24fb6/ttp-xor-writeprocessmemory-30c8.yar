rule TTP_XOR_WriteProcessMemory_30c8 {
  strings:
    $key_30c8 = { 67 ba [2] 55 98 [2] 53 ad [2] 7d ad [2] 42 b1 }

  condition:
    any of them
}