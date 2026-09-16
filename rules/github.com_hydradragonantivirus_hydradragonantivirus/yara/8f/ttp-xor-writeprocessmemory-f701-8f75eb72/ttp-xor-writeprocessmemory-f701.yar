rule TTP_XOR_WriteProcessMemory_f701 {
  strings:
    $key_f701 = { a0 73 [2] 92 51 [2] 94 64 [2] ba 64 [2] 85 78 }

  condition:
    any of them
}