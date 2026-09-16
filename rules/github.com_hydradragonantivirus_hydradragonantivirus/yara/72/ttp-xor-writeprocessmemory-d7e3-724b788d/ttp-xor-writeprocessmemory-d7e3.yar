rule TTP_XOR_WriteProcessMemory_d7e3 {
  strings:
    $key_d7e3 = { 80 91 [2] b2 b3 [2] b4 86 [2] 9a 86 [2] a5 9a }

  condition:
    any of them
}