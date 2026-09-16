rule TTP_XOR_WriteProcessMemory_f1c5 {
  strings:
    $key_f1c5 = { a6 b7 [2] 94 95 [2] 92 a0 [2] bc a0 [2] 83 bc }

  condition:
    any of them
}