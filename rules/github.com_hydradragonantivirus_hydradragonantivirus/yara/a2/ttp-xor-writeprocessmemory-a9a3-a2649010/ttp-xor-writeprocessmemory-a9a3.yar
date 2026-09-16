rule TTP_XOR_WriteProcessMemory_a9a3 {
  strings:
    $key_a9a3 = { fe d1 [2] cc f3 [2] ca c6 [2] e4 c6 [2] db da }

  condition:
    any of them
}