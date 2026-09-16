rule TTP_XOR_WriteProcessMemory_3a5f {
  strings:
    $key_3a5f = { 6d 2d [2] 5f 0f [2] 59 3a [2] 77 3a [2] 48 26 }

  condition:
    any of them
}