rule TTP_XOR_WriteProcessMemory_c643 {
  strings:
    $key_c643 = { 91 31 [2] a3 13 [2] a5 26 [2] 8b 26 [2] b4 3a }

  condition:
    any of them
}