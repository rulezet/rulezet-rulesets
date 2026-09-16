rule TTP_XOR_WriteProcessMemory_565f {
  strings:
    $key_565f = { 01 2d [2] 33 0f [2] 35 3a [2] 1b 3a [2] 24 26 }

  condition:
    any of them
}