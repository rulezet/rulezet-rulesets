rule TTP_XOR_WriteProcessMemory_dc12 {
  strings:
    $key_dc12 = { 8b 60 [2] b9 42 [2] bf 77 [2] 91 77 [2] ae 6b }

  condition:
    any of them
}