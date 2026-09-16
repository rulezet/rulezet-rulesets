rule TTP_XOR_WriteProcessMemory_f0ce {
  strings:
    $key_f0ce = { a7 bc [2] 95 9e [2] 93 ab [2] bd ab [2] 82 b7 }

  condition:
    any of them
}