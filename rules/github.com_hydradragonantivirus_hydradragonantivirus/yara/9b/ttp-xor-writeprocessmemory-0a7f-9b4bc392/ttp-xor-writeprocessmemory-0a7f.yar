rule TTP_XOR_WriteProcessMemory_0a7f {
  strings:
    $key_0a7f = { 5d 0d [2] 6f 2f [2] 69 1a [2] 47 1a [2] 78 06 }

  condition:
    any of them
}