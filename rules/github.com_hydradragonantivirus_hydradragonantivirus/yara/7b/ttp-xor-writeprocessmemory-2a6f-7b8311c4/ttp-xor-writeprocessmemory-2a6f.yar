rule TTP_XOR_WriteProcessMemory_2a6f {
  strings:
    $key_2a6f = { 7d 1d [2] 4f 3f [2] 49 0a [2] 67 0a [2] 58 16 }

  condition:
    any of them
}