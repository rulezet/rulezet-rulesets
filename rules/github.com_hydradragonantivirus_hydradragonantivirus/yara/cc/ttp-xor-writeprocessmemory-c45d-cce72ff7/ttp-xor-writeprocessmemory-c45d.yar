rule TTP_XOR_WriteProcessMemory_c45d {
  strings:
    $key_c45d = { 93 2f [2] a1 0d [2] a7 38 [2] 89 38 [2] b6 24 }

  condition:
    any of them
}