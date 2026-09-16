rule TTP_XOR_WriteProcessMemory_11c8 {
  strings:
    $key_11c8 = { 46 ba [2] 74 98 [2] 72 ad [2] 5c ad [2] 63 b1 }

  condition:
    any of them
}