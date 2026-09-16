rule TTP_XOR_WriteProcessMemory_7878 {
  strings:
    $key_7878 = { 2f 0a [2] 1d 28 [2] 1b 1d [2] 35 1d [2] 0a 01 }

  condition:
    any of them
}