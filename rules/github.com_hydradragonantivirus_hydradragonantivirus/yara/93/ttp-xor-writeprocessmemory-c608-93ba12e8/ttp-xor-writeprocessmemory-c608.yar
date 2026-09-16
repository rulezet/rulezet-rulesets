rule TTP_XOR_WriteProcessMemory_c608 {
  strings:
    $key_c608 = { 91 7a [2] a3 58 [2] a5 6d [2] 8b 6d [2] b4 71 }

  condition:
    any of them
}