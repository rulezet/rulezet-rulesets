rule TTP_XOR_WriteProcessMemory_d10e {
  strings:
    $key_d10e = { 86 7c [2] b4 5e [2] b2 6b [2] 9c 6b [2] a3 77 }

  condition:
    any of them
}