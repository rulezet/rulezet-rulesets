rule TTP_XOR_WriteProcessMemory_ef12 {
  strings:
    $key_ef12 = { b8 60 [2] 8a 42 [2] 8c 77 [2] a2 77 [2] 9d 6b }

  condition:
    any of them
}