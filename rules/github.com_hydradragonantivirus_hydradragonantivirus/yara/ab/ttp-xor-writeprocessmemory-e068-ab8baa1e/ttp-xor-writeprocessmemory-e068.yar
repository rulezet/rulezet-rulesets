rule TTP_XOR_WriteProcessMemory_e068 {
  strings:
    $key_e068 = { b7 1a [2] 85 38 [2] 83 0d [2] ad 0d [2] 92 11 }

  condition:
    any of them
}