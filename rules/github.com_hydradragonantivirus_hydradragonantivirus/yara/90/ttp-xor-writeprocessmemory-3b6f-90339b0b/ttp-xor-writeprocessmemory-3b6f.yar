rule TTP_XOR_WriteProcessMemory_3b6f {
  strings:
    $key_3b6f = { 6c 1d [2] 5e 3f [2] 58 0a [2] 76 0a [2] 49 16 }

  condition:
    any of them
}