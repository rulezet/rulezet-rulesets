rule TTP_XOR_WriteProcessMemory_c66c {
  strings:
    $key_c66c = { 91 1e [2] a3 3c [2] a5 09 [2] 8b 09 [2] b4 15 }

  condition:
    any of them
}