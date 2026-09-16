rule TTP_XOR_WriteProcessMemory_c67e {
  strings:
    $key_c67e = { 91 0c [2] a3 2e [2] a5 1b [2] 8b 1b [2] b4 07 }

  condition:
    any of them
}