rule TTP_XOR_WriteProcessMemory_2358 {
  strings:
    $key_2358 = { 74 2a [2] 46 08 [2] 40 3d [2] 6e 3d [2] 51 21 }

  condition:
    any of them
}