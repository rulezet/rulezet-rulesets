rule TTP_XOR_WriteProcessMemory_3b58 {
  strings:
    $key_3b58 = { 6c 2a [2] 5e 08 [2] 58 3d [2] 76 3d [2] 49 21 }

  condition:
    any of them
}