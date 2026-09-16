rule TTP_XOR_WriteProcessMemory_6258 {
  strings:
    $key_6258 = { 35 2a [2] 07 08 [2] 01 3d [2] 2f 3d [2] 10 21 }

  condition:
    any of them
}