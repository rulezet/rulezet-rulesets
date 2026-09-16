rule TTP_XOR_WriteProcessMemory_e04d {
  strings:
    $key_e04d = { b7 3f [2] 85 1d [2] 83 28 [2] ad 28 [2] 92 34 }

  condition:
    any of them
}