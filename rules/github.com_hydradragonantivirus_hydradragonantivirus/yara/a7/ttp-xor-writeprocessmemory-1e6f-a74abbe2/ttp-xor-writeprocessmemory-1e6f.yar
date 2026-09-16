rule TTP_XOR_WriteProcessMemory_1e6f {
  strings:
    $key_1e6f = { 49 1d [2] 7b 3f [2] 7d 0a [2] 53 0a [2] 6c 16 }

  condition:
    any of them
}