rule TTP_XOR_WriteProcessMemory_d9fb {
  strings:
    $key_d9fb = { 8e 89 [2] bc ab [2] ba 9e [2] 94 9e [2] ab 82 }

  condition:
    any of them
}