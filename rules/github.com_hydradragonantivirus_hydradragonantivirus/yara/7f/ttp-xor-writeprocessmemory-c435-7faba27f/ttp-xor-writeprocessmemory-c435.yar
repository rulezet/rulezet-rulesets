rule TTP_XOR_WriteProcessMemory_c435 {
  strings:
    $key_c435 = { 93 47 [2] a1 65 [2] a7 50 [2] 89 50 [2] b6 4c }

  condition:
    any of them
}