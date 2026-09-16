rule TTP_XOR_WriteProcessMemory_c02b {
  strings:
    $key_c02b = { 97 59 [2] a5 7b [2] a3 4e [2] 8d 4e [2] b2 52 }

  condition:
    any of them
}