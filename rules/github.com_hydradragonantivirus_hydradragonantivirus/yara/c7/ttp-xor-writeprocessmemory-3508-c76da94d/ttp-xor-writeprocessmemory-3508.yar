rule TTP_XOR_WriteProcessMemory_3508 {
  strings:
    $key_3508 = { 62 7a [2] 50 58 [2] 56 6d [2] 78 6d [2] 47 71 }

  condition:
    any of them
}