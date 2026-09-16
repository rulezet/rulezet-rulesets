rule TTP_XOR_WriteProcessMemory_e658 {
  strings:
    $key_e658 = { b1 2a [2] 83 08 [2] 85 3d [2] ab 3d [2] 94 21 }

  condition:
    any of them
}