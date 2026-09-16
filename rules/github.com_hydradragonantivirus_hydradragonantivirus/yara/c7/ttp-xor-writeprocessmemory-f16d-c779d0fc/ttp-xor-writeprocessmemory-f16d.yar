rule TTP_XOR_WriteProcessMemory_f16d {
  strings:
    $key_f16d = { a6 1f [2] 94 3d [2] 92 08 [2] bc 08 [2] 83 14 }

  condition:
    any of them
}