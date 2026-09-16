rule TTP_XOR_WriteProcessMemory_2878 {
  strings:
    $key_2878 = { 7f 0a [2] 4d 28 [2] 4b 1d [2] 65 1d [2] 5a 01 }

  condition:
    any of them
}