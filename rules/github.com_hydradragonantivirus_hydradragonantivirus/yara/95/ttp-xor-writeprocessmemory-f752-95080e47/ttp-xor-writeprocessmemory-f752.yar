rule TTP_XOR_WriteProcessMemory_f752 {
  strings:
    $key_f752 = { a0 20 [2] 92 02 [2] 94 37 [2] ba 37 [2] 85 2b }

  condition:
    any of them
}