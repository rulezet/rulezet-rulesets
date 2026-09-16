rule TTP_XOR_WriteProcessMemory_f38b {
  strings:
    $key_f38b = { a4 f9 [2] 96 db [2] 90 ee [2] be ee [2] 81 f2 }

  condition:
    any of them
}