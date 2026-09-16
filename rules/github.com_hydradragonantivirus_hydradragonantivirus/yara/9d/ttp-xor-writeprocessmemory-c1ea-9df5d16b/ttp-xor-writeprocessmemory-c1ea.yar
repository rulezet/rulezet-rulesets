rule TTP_XOR_WriteProcessMemory_c1ea {
  strings:
    $key_c1ea = { 96 98 [2] a4 ba [2] a2 8f [2] 8c 8f [2] b3 93 }

  condition:
    any of them
}