rule TTP_XOR_WriteProcessMemory_765f {
  strings:
    $key_765f = { 21 2d [2] 13 0f [2] 15 3a [2] 3b 3a [2] 04 26 }

  condition:
    any of them
}