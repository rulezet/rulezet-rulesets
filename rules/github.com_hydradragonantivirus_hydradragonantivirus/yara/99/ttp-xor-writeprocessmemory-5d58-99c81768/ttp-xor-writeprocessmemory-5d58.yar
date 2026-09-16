rule TTP_XOR_WriteProcessMemory_5d58 {
  strings:
    $key_5d58 = { 0a 2a [2] 38 08 [2] 3e 3d [2] 10 3d [2] 2f 21 }

  condition:
    any of them
}