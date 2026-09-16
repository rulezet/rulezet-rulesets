rule TTP_XOR_WriteProcessMemory_d71b {
  strings:
    $key_d71b = { 80 69 [2] b2 4b [2] b4 7e [2] 9a 7e [2] a5 62 }

  condition:
    any of them
}