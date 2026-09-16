rule TTP_XOR_WriteProcessMemory_d71e {
  strings:
    $key_d71e = { 80 6c [2] b2 4e [2] b4 7b [2] 9a 7b [2] a5 67 }

  condition:
    any of them
}