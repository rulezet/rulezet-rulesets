rule TTP_XOR_WriteProcessMemory_5a28 {
  strings:
    $key_5a28 = { 0d 5a [2] 3f 78 [2] 39 4d [2] 17 4d [2] 28 51 }

  condition:
    any of them
}