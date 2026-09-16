rule TTP_XOR_WriteProcessMemory_afe9 {
  strings:
    $key_afe9 = { f8 9b [2] ca b9 [2] cc 8c [2] e2 8c [2] dd 90 }

  condition:
    any of them
}