rule TTP_XOR_WriteProcessMemory_0108 {
  strings:
    $key_0108 = { 56 7a [2] 64 58 [2] 62 6d [2] 4c 6d [2] 73 71 }

  condition:
    any of them
}