rule TTP_XOR_WriteProcessMemory_f763 {
  strings:
    $key_f763 = { a0 11 [2] 92 33 [2] 94 06 [2] ba 06 [2] 85 1a }

  condition:
    any of them
}