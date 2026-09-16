rule TTP_XOR_WriteProcessMemory_d27d {
  strings:
    $key_d27d = { 85 0f [2] b7 2d [2] b1 18 [2] 9f 18 [2] a0 04 }

  condition:
    any of them
}