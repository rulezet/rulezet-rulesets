rule TTP_XOR_WriteProcessMemory_c02d {
  strings:
    $key_c02d = { 97 5f [2] a5 7d [2] a3 48 [2] 8d 48 [2] b2 54 }

  condition:
    any of them
}