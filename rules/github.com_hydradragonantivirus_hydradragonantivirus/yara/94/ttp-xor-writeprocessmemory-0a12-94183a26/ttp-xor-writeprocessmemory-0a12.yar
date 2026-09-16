rule TTP_XOR_WriteProcessMemory_0a12 {
  strings:
    $key_0a12 = { 5d 60 [2] 6f 42 [2] 69 77 [2] 47 77 [2] 78 6b }

  condition:
    any of them
}