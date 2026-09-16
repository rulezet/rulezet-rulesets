rule TTP_XOR_WriteProcessMemory_d4ea {
  strings:
    $key_d4ea = { 83 98 [2] b1 ba [2] b7 8f [2] 99 8f [2] a6 93 }

  condition:
    any of them
}