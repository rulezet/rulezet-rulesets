rule TTP_XOR_WriteProcessMemory_d41e {
  strings:
    $key_d41e = { 83 6c [2] b1 4e [2] b7 7b [2] 99 7b [2] a6 67 }

  condition:
    any of them
}