rule TTP_XOR_WriteProcessMemory_0add {
  strings:
    $key_0add = { 5d af [2] 6f 8d [2] 69 b8 [2] 47 b8 [2] 78 a4 }

  condition:
    any of them
}