rule TTP_XOR_WriteProcessMemory_7d58 {
  strings:
    $key_7d58 = { 2a 2a [2] 18 08 [2] 1e 3d [2] 30 3d [2] 0f 21 }

  condition:
    any of them
}