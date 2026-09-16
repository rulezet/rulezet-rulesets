rule TTP_XOR_WriteProcessMemory_20c8 {
  strings:
    $key_20c8 = { 77 ba [2] 45 98 [2] 43 ad [2] 6d ad [2] 52 b1 }

  condition:
    any of them
}