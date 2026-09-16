rule TTP_XOR_WriteProcessMemory_c62d {
  strings:
    $key_c62d = { 91 5f [2] a3 7d [2] a5 48 [2] 8b 48 [2] b4 54 }

  condition:
    any of them
}