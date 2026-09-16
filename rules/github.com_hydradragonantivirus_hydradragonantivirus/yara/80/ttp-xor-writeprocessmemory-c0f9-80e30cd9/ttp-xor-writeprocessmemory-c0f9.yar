rule TTP_XOR_WriteProcessMemory_c0f9 {
  strings:
    $key_c0f9 = { 97 8b [2] a5 a9 [2] a3 9c [2] 8d 9c [2] b2 80 }

  condition:
    any of them
}