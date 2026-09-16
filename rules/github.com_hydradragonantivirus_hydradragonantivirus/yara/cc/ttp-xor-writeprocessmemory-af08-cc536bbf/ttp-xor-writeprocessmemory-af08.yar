rule TTP_XOR_WriteProcessMemory_af08 {
  strings:
    $key_af08 = { f8 7a [2] ca 58 [2] cc 6d [2] e2 6d [2] dd 71 }

  condition:
    any of them
}