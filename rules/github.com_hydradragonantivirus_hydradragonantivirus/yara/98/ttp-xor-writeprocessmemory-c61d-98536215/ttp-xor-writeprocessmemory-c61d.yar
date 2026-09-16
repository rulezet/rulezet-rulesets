rule TTP_XOR_WriteProcessMemory_c61d {
  strings:
    $key_c61d = { 91 6f [2] a3 4d [2] a5 78 [2] 8b 78 [2] b4 64 }

  condition:
    any of them
}