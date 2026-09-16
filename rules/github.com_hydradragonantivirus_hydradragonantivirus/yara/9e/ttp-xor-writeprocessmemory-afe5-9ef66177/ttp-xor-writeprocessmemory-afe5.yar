rule TTP_XOR_WriteProcessMemory_afe5 {
  strings:
    $key_afe5 = { f8 97 [2] ca b5 [2] cc 80 [2] e2 80 [2] dd 9c }

  condition:
    any of them
}