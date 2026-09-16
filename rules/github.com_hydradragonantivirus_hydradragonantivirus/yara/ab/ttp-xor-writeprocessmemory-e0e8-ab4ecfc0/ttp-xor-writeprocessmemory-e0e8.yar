rule TTP_XOR_WriteProcessMemory_e0e8 {
  strings:
    $key_e0e8 = { b7 9a [2] 85 b8 [2] 83 8d [2] ad 8d [2] 92 91 }

  condition:
    any of them
}