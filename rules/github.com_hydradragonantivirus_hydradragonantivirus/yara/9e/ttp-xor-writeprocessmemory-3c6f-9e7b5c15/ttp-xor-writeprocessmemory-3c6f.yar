rule TTP_XOR_WriteProcessMemory_3c6f {
  strings:
    $key_3c6f = { 6b 1d [2] 59 3f [2] 5f 0a [2] 71 0a [2] 4e 16 }

  condition:
    any of them
}