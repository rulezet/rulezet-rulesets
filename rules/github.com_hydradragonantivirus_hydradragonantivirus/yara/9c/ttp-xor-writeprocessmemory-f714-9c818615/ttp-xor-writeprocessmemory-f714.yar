rule TTP_XOR_WriteProcessMemory_f714 {
  strings:
    $key_f714 = { a0 66 [2] 92 44 [2] 94 71 [2] ba 71 [2] 85 6d }

  condition:
    any of them
}