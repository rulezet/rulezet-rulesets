rule TTP_XOR_WriteProcessMemory_af06 {
  strings:
    $key_af06 = { f8 74 [2] ca 56 [2] cc 63 [2] e2 63 [2] dd 7f }

  condition:
    any of them
}