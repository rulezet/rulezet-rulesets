rule TTP_XOR_WriteProcessMemory_0758 {
  strings:
    $key_0758 = { 50 2a [2] 62 08 [2] 64 3d [2] 4a 3d [2] 75 21 }

  condition:
    any of them
}