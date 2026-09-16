rule TTP_XOR_WriteProcessMemory_d03d {
  strings:
    $key_d03d = { 87 4f [2] b5 6d [2] b3 58 [2] 9d 58 [2] a2 44 }

  condition:
    any of them
}