rule TTP_XOR_WriteProcessMemory_c679 {
  strings:
    $key_c679 = { 91 0b [2] a3 29 [2] a5 1c [2] 8b 1c [2] b4 00 }

  condition:
    any of them
}