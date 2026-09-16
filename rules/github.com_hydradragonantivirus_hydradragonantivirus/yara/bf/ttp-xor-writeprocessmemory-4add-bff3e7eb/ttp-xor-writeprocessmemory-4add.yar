rule TTP_XOR_WriteProcessMemory_4add {
  strings:
    $key_4add = { 1d af [2] 2f 8d [2] 29 b8 [2] 07 b8 [2] 38 a4 }

  condition:
    any of them
}