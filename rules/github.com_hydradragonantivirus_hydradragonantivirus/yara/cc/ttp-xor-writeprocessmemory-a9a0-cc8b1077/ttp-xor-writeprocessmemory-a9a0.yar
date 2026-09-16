rule TTP_XOR_WriteProcessMemory_a9a0 {
  strings:
    $key_a9a0 = { fe d2 [2] cc f0 [2] ca c5 [2] e4 c5 [2] db d9 }

  condition:
    any of them
}