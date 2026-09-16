rule TTP_XOR_WriteProcessMemory_c07d {
  strings:
    $key_c07d = { 97 0f [2] a5 2d [2] a3 18 [2] 8d 18 [2] b2 04 }

  condition:
    any of them
}