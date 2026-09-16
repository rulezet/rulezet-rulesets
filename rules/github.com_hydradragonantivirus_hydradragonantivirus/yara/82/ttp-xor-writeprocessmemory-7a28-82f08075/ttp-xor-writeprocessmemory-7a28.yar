rule TTP_XOR_WriteProcessMemory_7a28 {
  strings:
    $key_7a28 = { 2d 5a [2] 1f 78 [2] 19 4d [2] 37 4d [2] 08 51 }

  condition:
    any of them
}