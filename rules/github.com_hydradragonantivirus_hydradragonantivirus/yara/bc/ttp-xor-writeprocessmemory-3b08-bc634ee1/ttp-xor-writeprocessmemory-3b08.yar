rule TTP_XOR_WriteProcessMemory_3b08 {
  strings:
    $key_3b08 = { 6c 7a [2] 5e 58 [2] 58 6d [2] 76 6d [2] 49 71 }

  condition:
    any of them
}