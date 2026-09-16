rule TTP_XOR_WriteProcessMemory_af36 {
  strings:
    $key_af36 = { f8 44 [2] ca 66 [2] cc 53 [2] e2 53 [2] dd 4f }

  condition:
    any of them
}