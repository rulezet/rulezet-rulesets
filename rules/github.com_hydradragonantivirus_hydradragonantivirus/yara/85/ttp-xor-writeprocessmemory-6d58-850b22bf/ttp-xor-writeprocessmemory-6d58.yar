rule TTP_XOR_WriteProcessMemory_6d58 {
  strings:
    $key_6d58 = { 3a 2a [2] 08 08 [2] 0e 3d [2] 20 3d [2] 1f 21 }

  condition:
    any of them
}