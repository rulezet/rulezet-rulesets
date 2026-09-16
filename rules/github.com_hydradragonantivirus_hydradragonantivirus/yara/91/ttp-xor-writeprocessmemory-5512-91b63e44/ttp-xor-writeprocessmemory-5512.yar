rule TTP_XOR_WriteProcessMemory_5512 {
  strings:
    $key_5512 = { 02 60 [2] 30 42 [2] 36 77 [2] 18 77 [2] 27 6b }

  condition:
    any of them
}