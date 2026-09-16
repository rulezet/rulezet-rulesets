rule TTP_XOR_WriteProcessMemory_c7e3 {
  strings:
    $key_c7e3 = { 90 91 [2] a2 b3 [2] a4 86 [2] 8a 86 [2] b5 9a }

  condition:
    any of them
}