rule TTP_XOR_WriteProcessMemory_d33d {
  strings:
    $key_d33d = { 84 4f [2] b6 6d [2] b0 58 [2] 9e 58 [2] a1 44 }

  condition:
    any of them
}