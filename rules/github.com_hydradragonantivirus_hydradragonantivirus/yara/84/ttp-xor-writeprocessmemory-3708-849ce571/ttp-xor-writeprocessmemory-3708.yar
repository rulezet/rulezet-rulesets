rule TTP_XOR_WriteProcessMemory_3708 {
  strings:
    $key_3708 = { 60 7a [2] 52 58 [2] 54 6d [2] 7a 6d [2] 45 71 }

  condition:
    any of them
}