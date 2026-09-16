rule TTP_XOR_WriteProcessMemory_7268 {
  strings:
    $key_7268 = { 25 1a [2] 17 38 [2] 11 0d [2] 3f 0d [2] 00 11 }

  condition:
    any of them
}