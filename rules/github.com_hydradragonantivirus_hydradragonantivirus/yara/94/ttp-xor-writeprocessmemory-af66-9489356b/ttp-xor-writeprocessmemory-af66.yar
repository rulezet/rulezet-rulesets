rule TTP_XOR_WriteProcessMemory_af66 {
  strings:
    $key_af66 = { f8 14 [2] ca 36 [2] cc 03 [2] e2 03 [2] dd 1f }

  condition:
    any of them
}