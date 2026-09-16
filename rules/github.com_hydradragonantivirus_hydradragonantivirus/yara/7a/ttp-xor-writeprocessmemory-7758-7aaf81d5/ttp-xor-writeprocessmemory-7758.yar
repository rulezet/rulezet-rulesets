rule TTP_XOR_WriteProcessMemory_7758 {
  strings:
    $key_7758 = { 20 2a [2] 12 08 [2] 14 3d [2] 3a 3d [2] 05 21 }

  condition:
    any of them
}