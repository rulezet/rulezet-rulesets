rule TTP_XOR_WriteProcessMemory_3308 {
  strings:
    $key_3308 = { 64 7a [2] 56 58 [2] 50 6d [2] 7e 6d [2] 41 71 }

  condition:
    any of them
}