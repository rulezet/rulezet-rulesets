rule TTP_XOR_WriteProcessMemory_16c8 {
  strings:
    $key_16c8 = { 41 ba [2] 73 98 [2] 75 ad [2] 5b ad [2] 64 b1 }

  condition:
    any of them
}