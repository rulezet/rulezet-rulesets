rule TTP_XOR_WriteProcessMemory_f6c8 {
  strings:
    $key_f6c8 = { a1 ba [2] 93 98 [2] 95 ad [2] bb ad [2] 84 b1 }

  condition:
    any of them
}