rule TTP_XOR_WriteProcessMemory_0008 {
  strings:
    $key_0008 = { 57 7a [2] 65 58 [2] 63 6d [2] 4d 6d [2] 72 71 }

  condition:
    any of them
}