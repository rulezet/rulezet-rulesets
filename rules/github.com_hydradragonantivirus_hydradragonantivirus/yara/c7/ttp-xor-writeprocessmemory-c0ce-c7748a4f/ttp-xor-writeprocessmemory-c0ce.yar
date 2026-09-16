rule TTP_XOR_WriteProcessMemory_c0ce {
  strings:
    $key_c0ce = { 97 bc [2] a5 9e [2] a3 ab [2] 8d ab [2] b2 b7 }

  condition:
    any of them
}