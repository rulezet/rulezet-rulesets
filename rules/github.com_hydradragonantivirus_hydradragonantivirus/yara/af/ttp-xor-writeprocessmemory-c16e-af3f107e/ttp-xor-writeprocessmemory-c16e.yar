rule TTP_XOR_WriteProcessMemory_c16e {
  strings:
    $key_c16e = { 96 1c [2] a4 3e [2] a2 0b [2] 8c 0b [2] b3 17 }

  condition:
    any of them
}