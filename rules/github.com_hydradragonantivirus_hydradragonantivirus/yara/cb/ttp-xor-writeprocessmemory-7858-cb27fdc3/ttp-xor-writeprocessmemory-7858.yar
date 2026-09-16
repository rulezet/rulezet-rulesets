rule TTP_XOR_WriteProcessMemory_7858 {
  strings:
    $key_7858 = { 2f 2a [2] 1d 08 [2] 1b 3d [2] 35 3d [2] 0a 21 }

  condition:
    any of them
}