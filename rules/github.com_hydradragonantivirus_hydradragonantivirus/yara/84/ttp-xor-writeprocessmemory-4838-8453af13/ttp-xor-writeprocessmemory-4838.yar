rule TTP_XOR_WriteProcessMemory_4838 {
  strings:
    $key_4838 = { 1f 4a [2] 2d 68 [2] 2b 5d [2] 05 5d [2] 3a 41 }

  condition:
    any of them
}