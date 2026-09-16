rule TTP_XOR_WriteProcessMemory_f7c8 {
  strings:
    $key_f7c8 = { a0 ba [2] 92 98 [2] 94 ad [2] ba ad [2] 85 b1 }

  condition:
    any of them
}