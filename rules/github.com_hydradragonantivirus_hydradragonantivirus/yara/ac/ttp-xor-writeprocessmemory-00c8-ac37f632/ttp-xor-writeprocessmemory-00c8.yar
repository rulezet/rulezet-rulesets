rule TTP_XOR_WriteProcessMemory_00c8 {
  strings:
    $key_00c8 = { 57 ba [2] 65 98 [2] 63 ad [2] 4d ad [2] 72 b1 }

  condition:
    any of them
}