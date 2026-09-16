rule TTP_XOR_WriteProcessMemory_6e6f {
  strings:
    $key_6e6f = { 39 1d [2] 0b 3f [2] 0d 0a [2] 23 0a [2] 1c 16 }

  condition:
    any of them
}