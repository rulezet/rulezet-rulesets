rule TTP_XOR_WriteProcessMemory_d335 {
  strings:
    $key_d335 = { 84 47 [2] b6 65 [2] b0 50 [2] 9e 50 [2] a1 4c }

  condition:
    any of them
}