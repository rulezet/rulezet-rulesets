rule TTP_XOR_WriteProcessMemory_6858 {
  strings:
    $key_6858 = { 3f 2a [2] 0d 08 [2] 0b 3d [2] 25 3d [2] 1a 21 }

  condition:
    any of them
}