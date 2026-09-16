rule TTP_XOR_WriteProcessMemory_a9d2 {
  strings:
    $key_a9d2 = { fe a0 [2] cc 82 [2] ca b7 [2] e4 b7 [2] db ab }

  condition:
    any of them
}