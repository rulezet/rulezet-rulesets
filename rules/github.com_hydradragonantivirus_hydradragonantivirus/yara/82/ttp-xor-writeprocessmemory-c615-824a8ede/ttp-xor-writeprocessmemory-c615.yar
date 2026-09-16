rule TTP_XOR_WriteProcessMemory_c615 {
  strings:
    $key_c615 = { 91 67 [2] a3 45 [2] a5 70 [2] 8b 70 [2] b4 6c }

  condition:
    any of them
}