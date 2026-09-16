rule TTP_XOR_WriteProcessMemory_0f7f {
  strings:
    $key_0f7f = { 58 0d [2] 6a 2f [2] 6c 1a [2] 42 1a [2] 7d 06 }

  condition:
    any of them
}