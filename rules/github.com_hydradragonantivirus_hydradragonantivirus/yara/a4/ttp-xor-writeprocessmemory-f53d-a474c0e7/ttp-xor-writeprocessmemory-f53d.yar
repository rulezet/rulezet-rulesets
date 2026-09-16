rule TTP_XOR_WriteProcessMemory_f53d {
  strings:
    $key_f53d = { a2 4f [2] 90 6d [2] 96 58 [2] b8 58 [2] 87 44 }

  condition:
    any of them
}