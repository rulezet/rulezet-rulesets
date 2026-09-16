rule TTP_XOR_WriteProcessMemory_0d58 {
  strings:
    $key_0d58 = { 5a 2a [2] 68 08 [2] 6e 3d [2] 40 3d [2] 7f 21 }

  condition:
    any of them
}