rule TTP_XOR_WriteProcessMemory_48e8 {
  strings:
    $key_48e8 = { 1f 9a [2] 2d b8 [2] 2b 8d [2] 05 8d [2] 3a 91 }

  condition:
    any of them
}