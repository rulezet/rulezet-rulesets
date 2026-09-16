rule TTP_XOR_WriteProcessMemory_1a3f {
  strings:
    $key_1a3f = { 4d 4d [2] 7f 6f [2] 79 5a [2] 57 5a [2] 68 46 }

  condition:
    any of them
}