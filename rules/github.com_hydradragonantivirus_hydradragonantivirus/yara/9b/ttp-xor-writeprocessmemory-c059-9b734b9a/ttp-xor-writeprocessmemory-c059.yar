rule TTP_XOR_WriteProcessMemory_c059 {
  strings:
    $key_c059 = { 97 2b [2] a5 09 [2] a3 3c [2] 8d 3c [2] b2 20 }

  condition:
    any of them
}