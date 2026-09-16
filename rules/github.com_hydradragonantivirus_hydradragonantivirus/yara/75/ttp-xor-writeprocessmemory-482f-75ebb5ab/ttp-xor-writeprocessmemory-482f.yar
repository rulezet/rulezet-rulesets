rule TTP_XOR_WriteProcessMemory_482f {
  strings:
    $key_482f = { 1f 5d [2] 2d 7f [2] 2b 4a [2] 05 4a [2] 3a 56 }

  condition:
    any of them
}