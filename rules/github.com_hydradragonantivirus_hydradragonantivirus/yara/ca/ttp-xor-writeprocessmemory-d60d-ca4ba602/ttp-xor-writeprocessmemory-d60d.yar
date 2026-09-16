rule TTP_XOR_WriteProcessMemory_d60d {
  strings:
    $key_d60d = { 81 7f [2] b3 5d [2] b5 68 [2] 9b 68 [2] a4 74 }

  condition:
    any of them
}