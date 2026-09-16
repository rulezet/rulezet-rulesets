rule TTP_XOR_WriteProcessMemory_d12e {
  strings:
    $key_d12e = { 86 5c [2] b4 7e [2] b2 4b [2] 9c 4b [2] a3 57 }

  condition:
    any of them
}