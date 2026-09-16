rule TTP_XOR_WriteProcessMemory_6f6f {
  strings:
    $key_6f6f = { 38 1d [2] 0a 3f [2] 0c 0a [2] 22 0a [2] 1d 16 }

  condition:
    any of them
}