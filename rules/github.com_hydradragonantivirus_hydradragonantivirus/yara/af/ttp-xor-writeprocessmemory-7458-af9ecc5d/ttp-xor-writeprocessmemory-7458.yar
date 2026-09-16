rule TTP_XOR_WriteProcessMemory_7458 {
  strings:
    $key_7458 = { 23 2a [2] 11 08 [2] 17 3d [2] 39 3d [2] 06 21 }

  condition:
    any of them
}