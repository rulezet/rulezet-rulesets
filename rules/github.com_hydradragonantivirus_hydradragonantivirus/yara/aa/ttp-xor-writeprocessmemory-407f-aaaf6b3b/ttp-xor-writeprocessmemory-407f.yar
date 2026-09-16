rule TTP_XOR_WriteProcessMemory_407f {
  strings:
    $key_407f = { 17 0d [2] 25 2f [2] 23 1a [2] 0d 1a [2] 32 06 }

  condition:
    any of them
}