rule TTP_XOR_WriteProcessMemory_d13b {
  strings:
    $key_d13b = { 86 49 [2] b4 6b [2] b2 5e [2] 9c 5e [2] a3 42 }

  condition:
    any of them
}