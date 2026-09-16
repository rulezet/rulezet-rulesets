rule TTP_XOR_WriteProcessMemory_f54d {
  strings:
    $key_f54d = { a2 3f [2] 90 1d [2] 96 28 [2] b8 28 [2] 87 34 }

  condition:
    any of them
}