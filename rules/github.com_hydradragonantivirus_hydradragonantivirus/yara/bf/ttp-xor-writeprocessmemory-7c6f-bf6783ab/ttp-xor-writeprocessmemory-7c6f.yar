rule TTP_XOR_WriteProcessMemory_7c6f {
  strings:
    $key_7c6f = { 2b 1d [2] 19 3f [2] 1f 0a [2] 31 0a [2] 0e 16 }

  condition:
    any of them
}