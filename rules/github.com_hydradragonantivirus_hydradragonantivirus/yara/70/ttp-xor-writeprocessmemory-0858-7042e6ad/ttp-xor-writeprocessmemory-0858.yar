rule TTP_XOR_WriteProcessMemory_0858 {
  strings:
    $key_0858 = { 5f 2a [2] 6d 08 [2] 6b 3d [2] 45 3d [2] 7a 21 }

  condition:
    any of them
}