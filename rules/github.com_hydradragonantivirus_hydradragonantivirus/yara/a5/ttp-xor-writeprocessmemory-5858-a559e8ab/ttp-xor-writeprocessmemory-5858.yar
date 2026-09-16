rule TTP_XOR_WriteProcessMemory_5858 {
  strings:
    $key_5858 = { 0f 2a [2] 3d 08 [2] 3b 3d [2] 15 3d [2] 2a 21 }

  condition:
    any of them
}