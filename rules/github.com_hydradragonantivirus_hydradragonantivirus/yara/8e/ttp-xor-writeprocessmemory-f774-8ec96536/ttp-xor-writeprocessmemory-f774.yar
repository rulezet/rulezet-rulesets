rule TTP_XOR_WriteProcessMemory_f774 {
  strings:
    $key_f774 = { a0 06 [2] 92 24 [2] 94 11 [2] ba 11 [2] 85 0d }

  condition:
    any of them
}