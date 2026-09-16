rule TTP_XOR_WriteProcessMemory_c0e3 {
  strings:
    $key_c0e3 = { 97 91 [2] a5 b3 [2] a3 86 [2] 8d 86 [2] b2 9a }

  condition:
    any of them
}