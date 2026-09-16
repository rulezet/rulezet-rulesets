rule TTP_XOR_WriteProcessMemory_58e8 {
  strings:
    $key_58e8 = { 0f 9a [2] 3d b8 [2] 3b 8d [2] 15 8d [2] 2a 91 }

  condition:
    any of them
}