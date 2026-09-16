rule TTP_XOR_WriteProcessMemory_c02c {
  strings:
    $key_c02c = { 97 5e [2] a5 7c [2] a3 49 [2] 8d 49 [2] b2 55 }

  condition:
    any of them
}