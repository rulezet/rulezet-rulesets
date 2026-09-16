rule TTP_XOR_WriteProcessMemory_c625 {
  strings:
    $key_c625 = { 91 57 [2] a3 75 [2] a5 40 [2] 8b 40 [2] b4 5c }

  condition:
    any of them
}