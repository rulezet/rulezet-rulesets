rule TTP_XOR_WriteProcessMemory_c635 {
  strings:
    $key_c635 = { 91 47 [2] a3 65 [2] a5 50 [2] 8b 50 [2] b4 4c }

  condition:
    any of them
}