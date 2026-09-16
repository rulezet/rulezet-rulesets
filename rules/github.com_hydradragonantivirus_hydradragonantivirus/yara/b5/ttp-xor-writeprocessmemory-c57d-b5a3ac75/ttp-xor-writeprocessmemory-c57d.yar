rule TTP_XOR_WriteProcessMemory_c57d {
  strings:
    $key_c57d = { 92 0f [2] a0 2d [2] a6 18 [2] 88 18 [2] b7 04 }

  condition:
    any of them
}