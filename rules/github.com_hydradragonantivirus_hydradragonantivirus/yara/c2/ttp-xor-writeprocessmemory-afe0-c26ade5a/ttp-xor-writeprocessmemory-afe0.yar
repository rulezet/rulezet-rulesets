rule TTP_XOR_WriteProcessMemory_afe0 {
  strings:
    $key_afe0 = { f8 92 [2] ca b0 [2] cc 85 [2] e2 85 [2] dd 99 }

  condition:
    any of them
}