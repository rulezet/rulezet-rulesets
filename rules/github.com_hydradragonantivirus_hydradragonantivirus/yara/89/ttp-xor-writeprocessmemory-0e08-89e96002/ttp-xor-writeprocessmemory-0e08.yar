rule TTP_XOR_WriteProcessMemory_0e08 {
  strings:
    $key_0e08 = { 59 7a [2] 6b 58 [2] 6d 6d [2] 43 6d [2] 7c 71 }

  condition:
    any of them
}