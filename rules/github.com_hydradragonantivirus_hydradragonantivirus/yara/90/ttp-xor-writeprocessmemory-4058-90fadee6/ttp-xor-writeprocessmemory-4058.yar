rule TTP_XOR_WriteProcessMemory_4058 {
  strings:
    $key_4058 = { 17 2a [2] 25 08 [2] 23 3d [2] 0d 3d [2] 32 21 }

  condition:
    any of them
}