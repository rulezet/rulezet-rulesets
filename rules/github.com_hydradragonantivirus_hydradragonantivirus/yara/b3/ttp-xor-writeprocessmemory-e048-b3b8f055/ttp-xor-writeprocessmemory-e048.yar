rule TTP_XOR_WriteProcessMemory_e048 {
  strings:
    $key_e048 = { b7 3a [2] 85 18 [2] 83 2d [2] ad 2d [2] 92 31 }

  condition:
    any of them
}