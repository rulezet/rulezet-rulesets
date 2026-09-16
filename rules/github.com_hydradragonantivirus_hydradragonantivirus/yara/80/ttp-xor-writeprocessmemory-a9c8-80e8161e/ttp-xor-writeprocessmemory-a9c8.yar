rule TTP_XOR_WriteProcessMemory_a9c8 {
  strings:
    $key_a9c8 = { fe ba [2] cc 98 [2] ca ad [2] e4 ad [2] db b1 }

  condition:
    any of them
}