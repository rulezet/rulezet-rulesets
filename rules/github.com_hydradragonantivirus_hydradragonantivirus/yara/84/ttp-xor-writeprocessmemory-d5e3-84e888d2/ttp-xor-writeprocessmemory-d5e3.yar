rule TTP_XOR_WriteProcessMemory_d5e3 {
  strings:
    $key_d5e3 = { 82 91 [2] b0 b3 [2] b6 86 [2] 98 86 [2] a7 9a }

  condition:
    any of them
}