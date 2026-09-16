rule TTP_XOR_WriteProcessMemory_c07e {
  strings:
    $key_c07e = { 97 0c [2] a5 2e [2] a3 1b [2] 8d 1b [2] b2 07 }

  condition:
    any of them
}