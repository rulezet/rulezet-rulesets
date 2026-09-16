rule TTP_XOR_WriteProcessMemory_711f {
  strings:
    $key_711f = { 26 6d [2] 14 4f [2] 12 7a [2] 3c 7a [2] 03 66 }

  condition:
    any of them
}