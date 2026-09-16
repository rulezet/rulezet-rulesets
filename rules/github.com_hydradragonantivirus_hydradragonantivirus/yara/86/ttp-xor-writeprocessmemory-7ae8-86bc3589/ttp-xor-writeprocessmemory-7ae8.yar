rule TTP_XOR_WriteProcessMemory_7ae8 {
  strings:
    $key_7ae8 = { 2d 9a [2] 1f b8 [2] 19 8d [2] 37 8d [2] 08 91 }

  condition:
    any of them
}