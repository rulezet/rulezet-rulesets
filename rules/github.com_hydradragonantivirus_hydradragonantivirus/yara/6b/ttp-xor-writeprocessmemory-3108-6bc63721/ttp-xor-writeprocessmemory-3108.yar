rule TTP_XOR_WriteProcessMemory_3108 {
  strings:
    $key_3108 = { 66 7a [2] 54 58 [2] 52 6d [2] 7c 6d [2] 43 71 }

  condition:
    any of them
}