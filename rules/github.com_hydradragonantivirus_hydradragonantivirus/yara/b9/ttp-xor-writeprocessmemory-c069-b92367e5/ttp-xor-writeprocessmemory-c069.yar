rule TTP_XOR_WriteProcessMemory_c069 {
  strings:
    $key_c069 = { 97 1b [2] a5 39 [2] a3 0c [2] 8d 0c [2] b2 10 }

  condition:
    any of them
}