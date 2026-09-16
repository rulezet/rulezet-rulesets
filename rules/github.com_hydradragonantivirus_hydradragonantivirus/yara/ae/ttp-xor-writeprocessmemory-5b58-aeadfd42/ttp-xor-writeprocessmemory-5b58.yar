rule TTP_XOR_WriteProcessMemory_5b58 {
  strings:
    $key_5b58 = { 0c 2a [2] 3e 08 [2] 38 3d [2] 16 3d [2] 29 21 }

  condition:
    any of them
}