rule TTP_XOR_WriteProcessMemory_0a08 {
  strings:
    $key_0a08 = { 5d 7a [2] 6f 58 [2] 69 6d [2] 47 6d [2] 78 71 }

  condition:
    any of them
}