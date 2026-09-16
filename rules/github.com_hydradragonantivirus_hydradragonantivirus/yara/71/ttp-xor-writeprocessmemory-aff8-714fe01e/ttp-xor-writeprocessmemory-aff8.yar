rule TTP_XOR_WriteProcessMemory_aff8 {
  strings:
    $key_aff8 = { f8 8a [2] ca a8 [2] cc 9d [2] e2 9d [2] dd 81 }

  condition:
    any of them
}