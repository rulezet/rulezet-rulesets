rule TTP_XOR_WriteProcessMemory_e06d {
  strings:
    $key_e06d = { b7 1f [2] 85 3d [2] 83 08 [2] ad 08 [2] 92 14 }

  condition:
    any of them
}