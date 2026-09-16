rule TTP_XOR_WriteProcessMemory_c63e {
  strings:
    $key_c63e = { 91 4c [2] a3 6e [2] a5 5b [2] 8b 5b [2] b4 47 }

  condition:
    any of them
}