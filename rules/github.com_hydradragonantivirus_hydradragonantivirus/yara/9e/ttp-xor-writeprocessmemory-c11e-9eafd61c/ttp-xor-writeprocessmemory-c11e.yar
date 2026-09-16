rule TTP_XOR_WriteProcessMemory_c11e {
  strings:
    $key_c11e = { 96 6c [2] a4 4e [2] a2 7b [2] 8c 7b [2] b3 67 }

  condition:
    any of them
}