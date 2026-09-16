rule TTP_XOR_WriteProcessMemory_5add {
  strings:
    $key_5add = { 0d af [2] 3f 8d [2] 39 b8 [2] 17 b8 [2] 28 a4 }

  condition:
    any of them
}