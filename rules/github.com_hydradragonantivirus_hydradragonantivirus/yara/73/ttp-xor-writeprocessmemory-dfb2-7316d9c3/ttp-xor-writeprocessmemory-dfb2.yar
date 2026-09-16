rule TTP_XOR_WriteProcessMemory_dfb2 {
  strings:
    $key_dfb2 = { 88 c0 [2] ba e2 [2] bc d7 [2] 92 d7 [2] ad cb }

  condition:
    any of them
}