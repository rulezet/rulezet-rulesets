rule TTP_XOR_WriteProcessMemory_3f58 {
  strings:
    $key_3f58 = { 68 2a [2] 5a 08 [2] 5c 3d [2] 72 3d [2] 4d 21 }

  condition:
    any of them
}