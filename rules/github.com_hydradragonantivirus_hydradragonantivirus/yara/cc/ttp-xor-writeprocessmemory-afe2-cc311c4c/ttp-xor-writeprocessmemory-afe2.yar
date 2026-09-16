rule TTP_XOR_WriteProcessMemory_afe2 {
  strings:
    $key_afe2 = { f8 90 [2] ca b2 [2] cc 87 [2] e2 87 [2] dd 9b }

  condition:
    any of them
}