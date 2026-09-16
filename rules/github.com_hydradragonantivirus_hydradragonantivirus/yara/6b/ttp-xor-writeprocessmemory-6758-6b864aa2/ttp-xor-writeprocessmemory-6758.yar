rule TTP_XOR_WriteProcessMemory_6758 {
  strings:
    $key_6758 = { 30 2a [2] 02 08 [2] 04 3d [2] 2a 3d [2] 15 21 }

  condition:
    any of them
}