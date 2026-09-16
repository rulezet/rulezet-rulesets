rule TTP_XOR_WriteProcessMemory_a9a2 {
  strings:
    $key_a9a2 = { fe d0 [2] cc f2 [2] ca c7 [2] e4 c7 [2] db db }

  condition:
    any of them
}