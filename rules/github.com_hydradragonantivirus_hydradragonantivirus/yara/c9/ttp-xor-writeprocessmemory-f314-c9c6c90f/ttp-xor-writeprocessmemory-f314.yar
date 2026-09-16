rule TTP_XOR_WriteProcessMemory_f314 {
  strings:
    $key_f314 = { a4 66 [2] 96 44 [2] 90 71 [2] be 71 [2] 81 6d }

  condition:
    any of them
}