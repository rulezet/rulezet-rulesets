rule TTP_XOR_WriteProcessMemory_f7ed {
  strings:
    $key_f7ed = { a0 9f [2] 92 bd [2] 94 88 [2] ba 88 [2] 85 94 }

  condition:
    any of them
}