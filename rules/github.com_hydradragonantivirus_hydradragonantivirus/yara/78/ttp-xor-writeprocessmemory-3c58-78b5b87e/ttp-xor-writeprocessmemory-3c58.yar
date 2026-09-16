rule TTP_XOR_WriteProcessMemory_3c58 {
  strings:
    $key_3c58 = { 6b 2a [2] 59 08 [2] 5f 3d [2] 71 3d [2] 4e 21 }

  condition:
    any of them
}