rule TTP_XOR_WriteProcessMemory_f704 {
  strings:
    $key_f704 = { a0 76 [2] 92 54 [2] 94 61 [2] ba 61 [2] 85 7d }

  condition:
    any of them
}