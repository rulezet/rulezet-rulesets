rule TTP_XOR_WriteProcessMemory_aff6 {
  strings:
    $key_aff6 = { f8 84 [2] ca a6 [2] cc 93 [2] e2 93 [2] dd 8f }

  condition:
    any of them
}