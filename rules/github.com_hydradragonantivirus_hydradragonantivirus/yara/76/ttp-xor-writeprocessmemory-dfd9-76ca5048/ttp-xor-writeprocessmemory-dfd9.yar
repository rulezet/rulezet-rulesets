rule TTP_XOR_WriteProcessMemory_dfd9 {
  strings:
    $key_dfd9 = { 88 ab [2] ba 89 [2] bc bc [2] 92 bc [2] ad a0 }

  condition:
    any of them
}