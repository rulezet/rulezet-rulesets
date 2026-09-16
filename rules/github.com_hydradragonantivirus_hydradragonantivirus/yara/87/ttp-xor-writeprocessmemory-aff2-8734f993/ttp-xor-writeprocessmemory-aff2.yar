rule TTP_XOR_WriteProcessMemory_aff2 {
  strings:
    $key_aff2 = { f8 80 [2] ca a2 [2] cc 97 [2] e2 97 [2] dd 8b }

  condition:
    any of them
}