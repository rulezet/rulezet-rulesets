rule TTP_XOR_WriteProcessMemory_0e5f {
  strings:
    $key_0e5f = { 59 2d [2] 6b 0f [2] 6d 3a [2] 43 3a [2] 7c 26 }

  condition:
    any of them
}