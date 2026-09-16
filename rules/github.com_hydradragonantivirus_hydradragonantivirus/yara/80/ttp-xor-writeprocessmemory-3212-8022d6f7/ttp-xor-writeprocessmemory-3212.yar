rule TTP_XOR_WriteProcessMemory_3212 {
  strings:
    $key_3212 = { 65 60 [2] 57 42 [2] 51 77 [2] 7f 77 [2] 40 6b }

  condition:
    any of them
}