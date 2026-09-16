rule TTP_XOR_WriteProcessMemory_da58 {
  strings:
    $key_da58 = { 8d 2a [2] bf 08 [2] b9 3d [2] 97 3d [2] a8 21 }

  condition:
    any of them
}