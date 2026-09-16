rule TTP_XOR_WriteProcessMemory_c03c {
  strings:
    $key_c03c = { 97 4e [2] a5 6c [2] a3 59 [2] 8d 59 [2] b2 45 }

  condition:
    any of them
}