rule TTP_XOR_WriteProcessMemory_c6e9 {
  strings:
    $key_c6e9 = { 91 9b [2] a3 b9 [2] a5 8c [2] 8b 8c [2] b4 90 }

  condition:
    any of them
}