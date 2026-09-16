rule TTP_XOR_WriteProcessMemory_5ae8 {
  strings:
    $key_5ae8 = { 0d 9a [2] 3f b8 [2] 39 8d [2] 17 8d [2] 28 91 }

  condition:
    any of them
}