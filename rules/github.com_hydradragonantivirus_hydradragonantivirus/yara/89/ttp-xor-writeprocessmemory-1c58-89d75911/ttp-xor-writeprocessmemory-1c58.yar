rule TTP_XOR_WriteProcessMemory_1c58 {
  strings:
    $key_1c58 = { 4b 2a [2] 79 08 [2] 7f 3d [2] 51 3d [2] 6e 21 }

  condition:
    any of them
}