rule TTP_XOR_WriteProcessMemory_34c8 {
  strings:
    $key_34c8 = { 63 ba [2] 51 98 [2] 57 ad [2] 79 ad [2] 46 b1 }

  condition:
    any of them
}