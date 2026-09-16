rule TTP_XOR_WriteProcessMemory_d1e3 {
  strings:
    $key_d1e3 = { 86 91 [2] b4 b3 [2] b2 86 [2] 9c 86 [2] a3 9a }

  condition:
    any of them
}