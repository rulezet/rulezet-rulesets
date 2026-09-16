rule TTP_XOR_WriteProcessMemory_4e5f {
  strings:
    $key_4e5f = { 19 2d [2] 2b 0f [2] 2d 3a [2] 03 3a [2] 3c 26 }

  condition:
    any of them
}