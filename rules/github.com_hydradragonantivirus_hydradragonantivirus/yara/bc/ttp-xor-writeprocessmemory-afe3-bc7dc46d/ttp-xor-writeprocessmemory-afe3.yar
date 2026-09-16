rule TTP_XOR_WriteProcessMemory_afe3 {
  strings:
    $key_afe3 = { f8 91 [2] ca b3 [2] cc 86 [2] e2 86 [2] dd 9a }

  condition:
    any of them
}