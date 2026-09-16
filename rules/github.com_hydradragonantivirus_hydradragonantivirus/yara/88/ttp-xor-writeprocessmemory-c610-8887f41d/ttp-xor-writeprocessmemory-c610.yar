rule TTP_XOR_WriteProcessMemory_c610 {
  strings:
    $key_c610 = { 91 62 [2] a3 40 [2] a5 75 [2] 8b 75 [2] b4 69 }

  condition:
    any of them
}