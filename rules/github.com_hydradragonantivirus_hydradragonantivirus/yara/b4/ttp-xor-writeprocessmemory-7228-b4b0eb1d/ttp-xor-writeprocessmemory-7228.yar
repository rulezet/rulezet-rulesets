rule TTP_XOR_WriteProcessMemory_7228 {
  strings:
    $key_7228 = { 25 5a [2] 17 78 [2] 11 4d [2] 3f 4d [2] 00 51 }

  condition:
    any of them
}