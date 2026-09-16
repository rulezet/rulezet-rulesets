rule TTP_XOR_WriteProcessMemory_f728 {
  strings:
    $key_f728 = { a0 5a [2] 92 78 [2] 94 4d [2] ba 4d [2] 85 51 }

  condition:
    any of them
}