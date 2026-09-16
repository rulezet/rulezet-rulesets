rule TTP_XOR_WriteProcessMemory_35c8 {
  strings:
    $key_35c8 = { 62 ba [2] 50 98 [2] 56 ad [2] 78 ad [2] 47 b1 }

  condition:
    any of them
}