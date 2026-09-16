rule TTP_XOR_WriteProcessMemory_d57d {
  strings:
    $key_d57d = { 82 0f [2] b0 2d [2] b6 18 [2] 98 18 [2] a7 04 }

  condition:
    any of them
}