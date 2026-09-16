rule TTP_XOR_WriteProcessMemory_7f58 {
  strings:
    $key_7f58 = { 28 2a [2] 1a 08 [2] 1c 3d [2] 32 3d [2] 0d 21 }

  condition:
    any of them
}