rule TTP_XOR_WriteProcessMemory_e078 {
  strings:
    $key_e078 = { b7 0a [2] 85 28 [2] 83 1d [2] ad 1d [2] 92 01 }

  condition:
    any of them
}