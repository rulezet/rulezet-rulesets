rule TTP_XOR_WriteProcessMemory_6e7f {
  strings:
    $key_6e7f = { 39 0d [2] 0b 2f [2] 0d 1a [2] 23 1a [2] 1c 06 }

  condition:
    any of them
}