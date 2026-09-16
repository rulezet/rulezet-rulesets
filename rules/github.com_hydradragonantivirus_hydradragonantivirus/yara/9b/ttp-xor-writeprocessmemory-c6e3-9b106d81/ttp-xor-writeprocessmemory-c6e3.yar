rule TTP_XOR_WriteProcessMemory_c6e3 {
  strings:
    $key_c6e3 = { 91 91 [2] a3 b3 [2] a5 86 [2] 8b 86 [2] b4 9a }

  condition:
    any of them
}