rule TTP_XOR_WriteProcessMemory_e07d {
  strings:
    $key_e07d = { b7 0f [2] 85 2d [2] 83 18 [2] ad 18 [2] 92 04 }

  condition:
    any of them
}