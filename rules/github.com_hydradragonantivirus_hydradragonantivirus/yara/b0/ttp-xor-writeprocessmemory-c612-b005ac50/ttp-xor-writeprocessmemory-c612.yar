rule TTP_XOR_WriteProcessMemory_c612 {
  strings:
    $key_c612 = { 91 60 [2] a3 42 [2] a5 77 [2] 8b 77 [2] b4 6b }

  condition:
    any of them
}