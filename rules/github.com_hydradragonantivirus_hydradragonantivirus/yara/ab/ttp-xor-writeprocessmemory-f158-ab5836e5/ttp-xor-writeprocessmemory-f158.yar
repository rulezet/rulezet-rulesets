rule TTP_XOR_WriteProcessMemory_f158 {
  strings:
    $key_f158 = { a6 2a [2] 94 08 [2] 92 3d [2] bc 3d [2] 83 21 }

  condition:
    any of them
}