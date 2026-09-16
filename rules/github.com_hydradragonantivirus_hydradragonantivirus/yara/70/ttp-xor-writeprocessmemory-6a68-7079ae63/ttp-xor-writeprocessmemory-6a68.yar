rule TTP_XOR_WriteProcessMemory_6a68 {
  strings:
    $key_6a68 = { 3d 1a [2] 0f 38 [2] 09 0d [2] 27 0d [2] 18 11 }

  condition:
    any of them
}