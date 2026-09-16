rule TTP_XOR_WriteProcessMemory_1e7f {
  strings:
    $key_1e7f = { 49 0d [2] 7b 2f [2] 7d 1a [2] 53 1a [2] 6c 06 }

  condition:
    any of them
}