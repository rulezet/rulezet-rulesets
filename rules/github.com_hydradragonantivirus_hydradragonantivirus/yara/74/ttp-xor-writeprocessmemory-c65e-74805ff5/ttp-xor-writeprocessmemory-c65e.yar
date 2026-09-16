rule TTP_XOR_WriteProcessMemory_c65e {
  strings:
    $key_c65e = { 91 2c [2] a3 0e [2] a5 3b [2] 8b 3b [2] b4 27 }

  condition:
    any of them
}