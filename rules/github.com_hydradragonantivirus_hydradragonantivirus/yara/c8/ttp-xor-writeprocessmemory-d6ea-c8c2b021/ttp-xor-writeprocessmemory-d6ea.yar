rule TTP_XOR_WriteProcessMemory_d6ea {
  strings:
    $key_d6ea = { 81 98 [2] b3 ba [2] b5 8f [2] 9b 8f [2] a4 93 }

  condition:
    any of them
}