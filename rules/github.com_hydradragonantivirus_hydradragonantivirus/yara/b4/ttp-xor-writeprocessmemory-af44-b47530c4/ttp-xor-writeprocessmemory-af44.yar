rule TTP_XOR_WriteProcessMemory_af44 {
  strings:
    $key_af44 = { f8 36 [2] ca 14 [2] cc 21 [2] e2 21 [2] dd 3d }

  condition:
    any of them
}