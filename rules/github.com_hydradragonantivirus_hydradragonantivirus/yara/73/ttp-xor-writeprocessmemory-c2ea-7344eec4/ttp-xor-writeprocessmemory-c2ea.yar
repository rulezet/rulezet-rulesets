rule TTP_XOR_WriteProcessMemory_c2ea {
  strings:
    $key_c2ea = { 95 98 [2] a7 ba [2] a1 8f [2] 8f 8f [2] b0 93 }

  condition:
    any of them
}