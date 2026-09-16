rule TTP_XOR_WriteProcessMemory_0e7f {
  strings:
    $key_0e7f = { 59 0d [2] 6b 2f [2] 6d 1a [2] 43 1a [2] 7c 06 }

  condition:
    any of them
}