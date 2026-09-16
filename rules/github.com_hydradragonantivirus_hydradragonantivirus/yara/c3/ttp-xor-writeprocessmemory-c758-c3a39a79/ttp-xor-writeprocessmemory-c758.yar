rule TTP_XOR_WriteProcessMemory_c758 {
  strings:
    $key_c758 = { 90 2a [2] a2 08 [2] a4 3d [2] 8a 3d [2] b5 21 }

  condition:
    any of them
}