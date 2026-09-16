rule TTP_XOR_WriteProcessMemory_a989 {
  strings:
    $key_a989 = { fe fb [2] cc d9 [2] ca ec [2] e4 ec [2] db f0 }

  condition:
    any of them
}