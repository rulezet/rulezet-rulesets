rule TTP_XOR_WriteProcessMemory_3c68 {
  strings:
    $key_3c68 = { 6b 1a [2] 59 38 [2] 5f 0d [2] 71 0d [2] 4e 11 }

  condition:
    any of them
}