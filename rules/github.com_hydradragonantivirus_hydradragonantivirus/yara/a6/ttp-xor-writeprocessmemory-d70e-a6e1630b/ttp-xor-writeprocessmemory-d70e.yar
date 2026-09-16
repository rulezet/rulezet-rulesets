rule TTP_XOR_WriteProcessMemory_d70e {
  strings:
    $key_d70e = { 80 7c [2] b2 5e [2] b4 6b [2] 9a 6b [2] a5 77 }

  condition:
    any of them
}