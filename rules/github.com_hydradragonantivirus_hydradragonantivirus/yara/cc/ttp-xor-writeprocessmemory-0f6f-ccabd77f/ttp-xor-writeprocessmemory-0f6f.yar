rule TTP_XOR_WriteProcessMemory_0f6f {
  strings:
    $key_0f6f = { 58 1d [2] 6a 3f [2] 6c 0a [2] 42 0a [2] 7d 16 }

  condition:
    any of them
}