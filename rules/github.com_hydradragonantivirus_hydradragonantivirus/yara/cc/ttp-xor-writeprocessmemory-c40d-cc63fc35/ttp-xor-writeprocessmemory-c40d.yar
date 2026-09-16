rule TTP_XOR_WriteProcessMemory_c40d {
  strings:
    $key_c40d = { 93 7f [2] a1 5d [2] a7 68 [2] 89 68 [2] b6 74 }

  condition:
    any of them
}