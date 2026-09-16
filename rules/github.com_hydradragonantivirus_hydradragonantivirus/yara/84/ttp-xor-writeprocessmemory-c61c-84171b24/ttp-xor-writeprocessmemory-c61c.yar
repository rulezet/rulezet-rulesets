rule TTP_XOR_WriteProcessMemory_c61c {
  strings:
    $key_c61c = { 91 6e [2] a3 4c [2] a5 79 [2] 8b 79 [2] b4 65 }

  condition:
    any of them
}