rule TTP_XOR_WriteProcessMemory_726f {
  strings:
    $key_726f = { 25 1d [2] 17 3f [2] 11 0a [2] 3f 0a [2] 00 16 }

  condition:
    any of them
}