rule TTP_XOR_WriteProcessMemory_4ae8 {
  strings:
    $key_4ae8 = { 1d 9a [2] 2f b8 [2] 29 8d [2] 07 8d [2] 38 91 }

  condition:
    any of them
}