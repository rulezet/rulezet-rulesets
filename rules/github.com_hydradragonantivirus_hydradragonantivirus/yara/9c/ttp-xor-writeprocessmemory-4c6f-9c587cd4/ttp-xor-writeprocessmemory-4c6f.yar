rule TTP_XOR_WriteProcessMemory_4c6f {
  strings:
    $key_4c6f = { 1b 1d [2] 29 3f [2] 2f 0a [2] 01 0a [2] 3e 16 }

  condition:
    any of them
}