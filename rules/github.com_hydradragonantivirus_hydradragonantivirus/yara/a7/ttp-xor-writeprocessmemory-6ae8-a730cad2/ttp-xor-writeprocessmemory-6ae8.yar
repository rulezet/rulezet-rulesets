rule TTP_XOR_WriteProcessMemory_6ae8 {
  strings:
    $key_6ae8 = { 3d 9a [2] 0f b8 [2] 09 8d [2] 27 8d [2] 18 91 }

  condition:
    any of them
}