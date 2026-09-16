rule TTP_XOR_WriteProcessMemory_6a18 {
  strings:
    $key_6a18 = { 3d 6a [2] 0f 48 [2] 09 7d [2] 27 7d [2] 18 61 }

  condition:
    any of them
}