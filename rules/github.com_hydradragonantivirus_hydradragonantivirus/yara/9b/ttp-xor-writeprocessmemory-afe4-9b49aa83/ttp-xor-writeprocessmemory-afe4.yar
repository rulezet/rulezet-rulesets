rule TTP_XOR_WriteProcessMemory_afe4 {
  strings:
    $key_afe4 = { f8 96 [2] ca b4 [2] cc 81 [2] e2 81 [2] dd 9d }

  condition:
    any of them
}