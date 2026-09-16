rule TTP_XOR_WriteProcessMemory_6d6f {
  strings:
    $key_6d6f = { 3a 1d [2] 08 3f [2] 0e 0a [2] 20 0a [2] 1f 16 }

  condition:
    any of them
}