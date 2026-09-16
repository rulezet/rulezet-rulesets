rule TTP_XOR_WriteProcessMemory_c135 {
  strings:
    $key_c135 = { 96 47 [2] a4 65 [2] a2 50 [2] 8c 50 [2] b3 4c }

  condition:
    any of them
}