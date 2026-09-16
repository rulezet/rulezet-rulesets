rule TTP_XOR_WriteProcessMemory_d61b {
  strings:
    $key_d61b = { 81 69 [2] b3 4b [2] b5 7e [2] 9b 7e [2] a4 62 }

  condition:
    any of them
}