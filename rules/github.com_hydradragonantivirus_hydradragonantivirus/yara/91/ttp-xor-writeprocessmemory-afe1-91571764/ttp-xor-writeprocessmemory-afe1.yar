rule TTP_XOR_WriteProcessMemory_afe1 {
  strings:
    $key_afe1 = { f8 93 [2] ca b1 [2] cc 84 [2] e2 84 [2] dd 98 }

  condition:
    any of them
}