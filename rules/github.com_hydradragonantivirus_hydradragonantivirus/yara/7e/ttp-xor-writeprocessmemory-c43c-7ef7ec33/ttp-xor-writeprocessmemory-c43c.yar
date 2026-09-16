rule TTP_XOR_WriteProcessMemory_c43c {
  strings:
    $key_c43c = { 93 4e [2] a1 6c [2] a7 59 [2] 89 59 [2] b6 45 }

  condition:
    any of them
}