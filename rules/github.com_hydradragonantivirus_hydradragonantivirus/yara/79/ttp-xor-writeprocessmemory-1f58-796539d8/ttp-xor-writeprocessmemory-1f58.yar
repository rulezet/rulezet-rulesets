rule TTP_XOR_WriteProcessMemory_1f58 {
  strings:
    $key_1f58 = { 48 2a [2] 7a 08 [2] 7c 3d [2] 52 3d [2] 6d 21 }

  condition:
    any of them
}