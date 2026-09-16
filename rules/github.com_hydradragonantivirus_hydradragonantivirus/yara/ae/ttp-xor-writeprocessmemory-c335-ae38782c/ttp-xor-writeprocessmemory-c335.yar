rule TTP_XOR_WriteProcessMemory_c335 {
  strings:
    $key_c335 = { 94 47 [2] a6 65 [2] a0 50 [2] 8e 50 [2] b1 4c }

  condition:
    any of them
}