rule TTP_XOR_WriteProcessMemory_1b58 {
  strings:
    $key_1b58 = { 4c 2a [2] 7e 08 [2] 78 3d [2] 56 3d [2] 69 21 }

  condition:
    any of them
}