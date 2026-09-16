rule TTP_XOR_WriteProcessMemory_1a1f {
  strings:
    $key_1a1f = { 4d 6d [2] 7f 4f [2] 79 7a [2] 57 7a [2] 68 66 }

  condition:
    any of them
}