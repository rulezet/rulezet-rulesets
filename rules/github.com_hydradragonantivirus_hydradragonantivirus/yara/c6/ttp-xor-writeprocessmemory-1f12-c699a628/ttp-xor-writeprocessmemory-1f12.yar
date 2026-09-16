rule TTP_XOR_WriteProcessMemory_1f12 {
  strings:
    $key_1f12 = { 48 60 [2] 7a 42 [2] 7c 77 [2] 52 77 [2] 6d 6b }

  condition:
    any of them
}