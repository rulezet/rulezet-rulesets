rule TTP_XOR_WriteProcessMemory_c4ea {
  strings:
    $key_c4ea = { 93 98 [2] a1 ba [2] a7 8f [2] 89 8f [2] b6 93 }

  condition:
    any of them
}