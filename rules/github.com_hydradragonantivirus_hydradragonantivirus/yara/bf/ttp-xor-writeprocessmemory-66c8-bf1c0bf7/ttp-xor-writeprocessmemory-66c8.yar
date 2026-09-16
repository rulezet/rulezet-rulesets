rule TTP_XOR_WriteProcessMemory_66c8 {
  strings:
    $key_66c8 = { 31 ba [2] 03 98 [2] 05 ad [2] 2b ad [2] 14 b1 }

  condition:
    any of them
}