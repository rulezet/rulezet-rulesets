rule TTP_XOR_WriteProcessMemory_3a6f {
  strings:
    $key_3a6f = { 6d 1d [2] 5f 3f [2] 59 0a [2] 77 0a [2] 48 16 }

  condition:
    any of them
}