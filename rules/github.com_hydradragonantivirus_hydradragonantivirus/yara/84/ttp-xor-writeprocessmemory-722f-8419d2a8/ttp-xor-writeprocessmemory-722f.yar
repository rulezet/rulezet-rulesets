rule TTP_XOR_WriteProcessMemory_722f {
  strings:
    $key_722f = { 25 5d [2] 17 7f [2] 11 4a [2] 3f 4a [2] 00 56 }

  condition:
    any of them
}