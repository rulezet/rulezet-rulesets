rule TTP_XOR_WriteProcessMemory_a9dd {
  strings:
    $key_a9dd = { fe af [2] cc 8d [2] ca b8 [2] e4 b8 [2] db a4 }

  condition:
    any of them
}