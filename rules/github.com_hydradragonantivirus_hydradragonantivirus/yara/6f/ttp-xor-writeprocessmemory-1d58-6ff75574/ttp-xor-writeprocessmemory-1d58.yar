rule TTP_XOR_WriteProcessMemory_1d58 {
  strings:
    $key_1d58 = { 4a 2a [2] 78 08 [2] 7e 3d [2] 50 3d [2] 6f 21 }

  condition:
    any of them
}