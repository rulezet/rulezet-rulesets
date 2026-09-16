rule TTP_XOR_WriteProcessMemory_f31d {
  strings:
    $key_f31d = { a4 6f [2] 96 4d [2] 90 78 [2] be 78 [2] 81 64 }

  condition:
    any of them
}