rule TTP_XOR_WriteProcessMemory_2268 {
  strings:
    $key_2268 = { 75 1a [2] 47 38 [2] 41 0d [2] 6f 0d [2] 50 11 }

  condition:
    any of them
}