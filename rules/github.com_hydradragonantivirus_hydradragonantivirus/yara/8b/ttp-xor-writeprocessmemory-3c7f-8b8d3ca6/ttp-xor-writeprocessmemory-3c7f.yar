rule TTP_XOR_WriteProcessMemory_3c7f {
  strings:
    $key_3c7f = { 6b 0d [2] 59 2f [2] 5f 1a [2] 71 1a [2] 4e 06 }

  condition:
    any of them
}