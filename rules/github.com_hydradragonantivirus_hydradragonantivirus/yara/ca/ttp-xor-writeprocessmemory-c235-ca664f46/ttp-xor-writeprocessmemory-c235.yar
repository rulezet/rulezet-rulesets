rule TTP_XOR_WriteProcessMemory_c235 {
  strings:
    $key_c235 = { 95 47 [2] a7 65 [2] a1 50 [2] 8f 50 [2] b0 4c }

  condition:
    any of them
}