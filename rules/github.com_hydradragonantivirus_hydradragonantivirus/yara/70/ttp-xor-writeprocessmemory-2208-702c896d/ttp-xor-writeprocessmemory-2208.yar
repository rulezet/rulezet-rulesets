rule TTP_XOR_WriteProcessMemory_2208 {
  strings:
    $key_2208 = { 75 7a [2] 47 58 [2] 41 6d [2] 6f 6d [2] 50 71 }

  condition:
    any of them
}