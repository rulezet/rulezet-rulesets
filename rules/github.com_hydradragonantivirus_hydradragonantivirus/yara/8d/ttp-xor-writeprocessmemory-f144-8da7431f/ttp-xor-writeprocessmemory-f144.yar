rule TTP_XOR_WriteProcessMemory_f144 {
  strings:
    $key_f144 = { a6 36 [2] 94 14 [2] 92 21 [2] bc 21 [2] 83 3d }

  condition:
    any of them
}