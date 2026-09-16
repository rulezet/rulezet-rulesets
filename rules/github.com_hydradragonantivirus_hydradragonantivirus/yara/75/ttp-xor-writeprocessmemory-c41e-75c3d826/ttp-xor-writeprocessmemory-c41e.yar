rule TTP_XOR_WriteProcessMemory_c41e {
  strings:
    $key_c41e = { 93 6c [2] a1 4e [2] a7 7b [2] 89 7b [2] b6 67 }

  condition:
    any of them
}