rule TTP_XOR_WriteProcessMemory_f61d {
  strings:
    $key_f61d = { a1 6f [2] 93 4d [2] 95 78 [2] bb 78 [2] 84 64 }

  condition:
    any of them
}