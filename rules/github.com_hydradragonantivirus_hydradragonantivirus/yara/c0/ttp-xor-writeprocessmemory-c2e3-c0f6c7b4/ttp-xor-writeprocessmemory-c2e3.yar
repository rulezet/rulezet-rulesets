rule TTP_XOR_WriteProcessMemory_c2e3 {
  strings:
    $key_c2e3 = { 95 91 [2] a7 b3 [2] a1 86 [2] 8f 86 [2] b0 9a }

  condition:
    any of them
}