rule TTP_XOR_WriteProcessMemory_d880 {
  strings:
    $key_d880 = { 8f f2 [2] bd d0 [2] bb e5 [2] 95 e5 [2] aa f9 }

  condition:
    any of them
}